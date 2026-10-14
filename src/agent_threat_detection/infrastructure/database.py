"""SQLAlchemy Core persistence. PostgreSQL in production; SQLite in tests.

Every write that belongs to one agent batch (profile, alerts, SIEM outbox,
processed event ids) commits in a single transaction. Profiles, alerts and
containment actions carry a version and are updated with compare-and-swap,
so two replicas processing the same agent cannot silently overwrite each other.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    Column,
    DateTime,
    Index,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    and_,
    delete,
    func,
    insert,
    select,
    update,
)
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, create_async_engine

from agent_threat_detection.detection.baseline import AgentProfile
from agent_threat_detection.domain.errors import ConflictError, NotFoundError
from agent_threat_detection.domain.findings import (
    Alert,
    AlertStatus,
    ContainmentAction,
    ContainmentStatus,
    Severity,
)

metadata = MetaData()

profiles = Table(
    "agent_profiles",
    metadata,
    Column("agent_id", String(512), primary_key=True),
    Column("version", Integer, nullable=False),
    Column("document", Text, nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
)

alerts = Table(
    "alerts",
    metadata,
    Column("alert_id", String(64), primary_key=True),
    Column("dedup_key", String(64), nullable=False),
    Column("agent_id", String(512), nullable=False),
    Column("status", String(32), nullable=False),
    Column("severity", Integer, nullable=False),
    Column("detector", String(128), nullable=False),
    Column("last_seen", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    Column("version", Integer, nullable=False),
    Column("document", Text, nullable=False),
    Index("ix_alerts_dedup", "dedup_key", "status"),
    Index("ix_alerts_agent", "agent_id"),
    Index("ix_alerts_status_updated", "status", "updated_at"),
)

containment = Table(
    "containment_actions",
    metadata,
    Column("containment_id", String(64), primary_key=True),
    Column("agent_id", String(512), nullable=False),
    Column("status", String(32), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    Column("version", Integer, nullable=False),
    Column("document", Text, nullable=False),
    Index("ix_containment_agent_status", "agent_id", "status"),
)

siem_outbox = Table(
    "siem_outbox",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("next_attempt_at", DateTime(timezone=True), nullable=False),
    Column("attempts", Integer, nullable=False, default=0),
    Column("delivered_at", DateTime(timezone=True), nullable=True),
    Column("payload", Text, nullable=False),
    Index("ix_outbox_due", "delivered_at", "next_attempt_at"),
)

processed_events = Table(
    "processed_events",
    metadata,
    Column("event_id", String(160), primary_key=True),
    Column("seen_at", DateTime(timezone=True), nullable=False),
    Index("ix_processed_seen", "seen_at"),
)

schema_version = Table(
    "schema_version",
    metadata,
    Column("version", Integer, primary_key=True),
)

SCHEMA_VERSION = 1
OPEN_STATUSES = tuple(s.value for s in AlertStatus if s.open)
ACTIVE_CONTAINMENT = tuple(s.value for s in ContainmentStatus if s.active)


def make_engine(url: str) -> AsyncEngine:
    return create_async_engine(url, pool_pre_ping=True)


async def create_schema(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        await conn.run_sync(metadata.create_all)
        current = (await conn.execute(select(schema_version.c.version))).scalar()
        if current is None:
            await conn.execute(insert(schema_version).values(version=SCHEMA_VERSION))


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


@dataclass(frozen=True)
class AlertWrite:
    """An alert to persist; ``previous_version`` is None for a new alert."""

    alert: Alert
    previous_version: int | None


@dataclass(frozen=True)
class OutboxItem:
    id: int
    attempts: int
    payload: str


@dataclass(frozen=True)
class AlertQuery:
    status: AlertStatus | None = None
    agent_id: str | None = None
    min_severity: Severity = Severity.INFORMATIONAL
    limit: int = 100
    offset: int = 0


class ThreatStore:
    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    # ------------------------------------------------------------------ profiles

    async def get_profile(self, agent_id: str) -> AgentProfile | None:
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(
                    select(profiles.c.document).where(profiles.c.agent_id == agent_id)
                )
            ).first()
        return AgentProfile.model_validate_json(row[0]) if row else None

    async def save_profile(self, profile: AgentProfile, *, expected_version: int) -> None:
        async with self._engine.begin() as conn:
            await self._write_profile(conn, profile, expected_version)

    @staticmethod
    async def _write_profile(
        conn: AsyncConnection, profile: AgentProfile, expected_version: int
    ) -> None:
        now = datetime.now(UTC)
        stored = profile.model_copy(update={"version": expected_version + 1})
        if expected_version == 0:
            exists = (
                await conn.execute(
                    select(profiles.c.agent_id).where(profiles.c.agent_id == profile.agent_id)
                )
            ).first()
            if exists:
                raise ConflictError(f"profile {profile.agent_id} was created concurrently")
            await conn.execute(
                insert(profiles).values(
                    agent_id=profile.agent_id,
                    version=stored.version,
                    document=stored.model_dump_json(),
                    updated_at=now,
                )
            )
        else:
            result = await conn.execute(
                update(profiles)
                .where(
                    and_(
                        profiles.c.agent_id == profile.agent_id,
                        profiles.c.version == expected_version,
                    )
                )
                .values(version=stored.version, document=stored.model_dump_json(), updated_at=now)
            )
            if result.rowcount == 0:
                raise ConflictError(f"profile {profile.agent_id} changed concurrently")
        profile.version = stored.version

    async def list_profiles(self, *, limit: int, offset: int) -> Sequence[AgentProfile]:
        query = select(profiles.c.document).order_by(profiles.c.agent_id).limit(limit)
        async with self._engine.connect() as conn:
            rows = (await conn.execute(query.offset(offset))).all()
        return [AgentProfile.model_validate_json(r[0]) for r in rows]

    # -------------------------------------------------------------- agent batch

    async def processed(self, event_ids: Iterable[str]) -> set[str]:
        ids = list(event_ids)
        if not ids:
            return set()
        async with self._engine.connect() as conn:
            rows = (
                await conn.execute(
                    select(processed_events.c.event_id).where(processed_events.c.event_id.in_(ids))
                )
            ).all()
        return {r[0] for r in rows}

    async def commit_batch(
        self,
        *,
        profile: AgentProfile,
        expected_version: int,
        alerts_to_write: Sequence[AlertWrite],
        outbox: Sequence[str],
        event_ids: Sequence[str],
        now: datetime,
    ) -> None:
        async with self._engine.begin() as conn:
            await self._write_profile(conn, profile, expected_version)
            for write in alerts_to_write:
                await self._write_alert(conn, write)
            if outbox:
                await conn.execute(
                    insert(siem_outbox),
                    [
                        {"created_at": now, "next_attempt_at": now, "attempts": 0, "payload": p}
                        for p in outbox
                    ],
                )
            if event_ids:
                await conn.execute(
                    insert(processed_events), [{"event_id": e, "seen_at": now} for e in event_ids]
                )

    async def purge_processed(self, before: datetime) -> int:
        async with self._engine.begin() as conn:
            result = await conn.execute(
                delete(processed_events).where(processed_events.c.seen_at < _aware(before))
            )
        return int(result.rowcount or 0)

    # -------------------------------------------------------------------- alerts

    @staticmethod
    def _alert_values(alert: Alert) -> dict[str, Any]:
        return {
            "dedup_key": alert.dedup_key,
            "agent_id": alert.agent_id,
            "status": alert.status.value,
            "severity": int(alert.severity),
            "detector": alert.detector,
            "last_seen": alert.last_seen,
            "updated_at": alert.updated_at,
            "version": alert.version,
            "document": alert.model_dump_json(),
        }

    async def _write_alert(self, conn: AsyncConnection, write: AlertWrite) -> None:
        values = self._alert_values(write.alert)
        if write.previous_version is None:
            await conn.execute(insert(alerts).values(alert_id=write.alert.alert_id, **values))
            return
        result = await conn.execute(
            update(alerts)
            .where(
                and_(
                    alerts.c.alert_id == write.alert.alert_id,
                    alerts.c.version == write.previous_version,
                )
            )
            .values(**values)
        )
        if result.rowcount == 0:
            raise ConflictError(f"alert {write.alert.alert_id} changed concurrently")

    async def save_alert(
        self, write: AlertWrite, *, now: datetime, outbox: Sequence[str] = ()
    ) -> None:
        async with self._engine.begin() as conn:
            await self._write_alert(conn, write)
            if outbox:
                await conn.execute(
                    insert(siem_outbox),
                    [
                        {"created_at": now, "next_attempt_at": now, "attempts": 0, "payload": p}
                        for p in outbox
                    ],
                )

    async def find_open_alert(self, dedup_key: str, *, since: datetime) -> Alert | None:
        query = (
            select(alerts.c.document)
            .where(
                and_(
                    alerts.c.dedup_key == dedup_key,
                    alerts.c.status.in_(OPEN_STATUSES),
                    alerts.c.last_seen >= _aware(since),
                )
            )
            .order_by(alerts.c.last_seen.desc())
            .limit(1)
        )
        async with self._engine.connect() as conn:
            row = (await conn.execute(query)).first()
        return Alert.model_validate_json(row[0]) if row else None

    async def get_alert(self, alert_id: str) -> Alert:
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(select(alerts.c.document).where(alerts.c.alert_id == alert_id))
            ).first()
        if row is None:
            raise NotFoundError(f"alert {alert_id} not found")
        return Alert.model_validate_json(row[0])

    async def list_alerts(self, query: AlertQuery) -> Sequence[Alert]:
        statement = select(alerts.c.document).where(alerts.c.severity >= int(query.min_severity))
        if query.status is not None:
            statement = statement.where(alerts.c.status == query.status.value)
        if query.agent_id is not None:
            statement = statement.where(alerts.c.agent_id == query.agent_id)
        statement = (
            statement.order_by(alerts.c.updated_at.desc(), alerts.c.alert_id)
            .limit(query.limit)
            .offset(query.offset)
        )
        async with self._engine.connect() as conn:
            rows = (await conn.execute(statement)).all()
        return [Alert.model_validate_json(r[0]) for r in rows]

    async def open_alert_counts(self) -> dict[int, int]:
        statement = (
            select(alerts.c.severity, func.count())
            .where(alerts.c.status.in_(OPEN_STATUSES))
            .group_by(alerts.c.severity)
        )
        async with self._engine.connect() as conn:
            rows = (await conn.execute(statement)).all()
        return {int(severity): int(count) for severity, count in rows}

    # --------------------------------------------------------------- containment

    async def add_containment(self, action: ContainmentAction) -> None:
        async with self._engine.begin() as conn:
            await conn.execute(
                insert(containment).values(
                    containment_id=action.containment_id,
                    agent_id=action.agent_id,
                    status=action.status.value,
                    updated_at=action.updated_at,
                    version=action.version,
                    document=action.model_dump_json(),
                )
            )

    async def update_containment(self, action: ContainmentAction, *, previous_version: int) -> None:
        async with self._engine.begin() as conn:
            result = await conn.execute(
                update(containment)
                .where(
                    and_(
                        containment.c.containment_id == action.containment_id,
                        containment.c.version == previous_version,
                    )
                )
                .values(
                    status=action.status.value,
                    updated_at=action.updated_at,
                    version=action.version,
                    document=action.model_dump_json(),
                )
            )
        if result.rowcount == 0:
            raise ConflictError(f"containment {action.containment_id} changed concurrently")

    async def get_containment(self, containment_id: str) -> ContainmentAction:
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(
                    select(containment.c.document).where(
                        containment.c.containment_id == containment_id
                    )
                )
            ).first()
        if row is None:
            raise NotFoundError(f"containment action {containment_id} not found")
        return ContainmentAction.model_validate_json(row[0])

    async def active_containment(self, agent_id: str) -> ContainmentAction | None:
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(
                    select(containment.c.document)
                    .where(
                        and_(
                            containment.c.agent_id == agent_id,
                            containment.c.status.in_(ACTIVE_CONTAINMENT),
                        )
                    )
                    .order_by(containment.c.updated_at.desc())
                    .limit(1)
                )
            ).first()
        return ContainmentAction.model_validate_json(row[0]) if row else None

    async def list_containment(
        self, *, status: ContainmentStatus | None, limit: int, offset: int
    ) -> Sequence[ContainmentAction]:
        statement = select(containment.c.document)
        if status is not None:
            statement = statement.where(containment.c.status == status.value)
        statement = (
            statement.order_by(containment.c.updated_at.desc(), containment.c.containment_id)
            .limit(limit)
            .offset(offset)
        )
        async with self._engine.connect() as conn:
            rows = (await conn.execute(statement)).all()
        return [ContainmentAction.model_validate_json(r[0]) for r in rows]

    # ------------------------------------------------------------------- outbox

    async def due_outbox(self, *, now: datetime, limit: int) -> Sequence[OutboxItem]:
        statement = (
            select(siem_outbox.c.id, siem_outbox.c.attempts, siem_outbox.c.payload)
            .where(
                and_(
                    siem_outbox.c.delivered_at.is_(None),
                    siem_outbox.c.next_attempt_at <= _aware(now),
                )
            )
            .order_by(siem_outbox.c.id)
            .limit(limit)
        )
        async with self._engine.connect() as conn:
            rows = (await conn.execute(statement)).all()
        return [OutboxItem(id=r[0], attempts=r[1], payload=r[2]) for r in rows]

    async def mark_delivered(self, ids: Sequence[int], *, at: datetime) -> None:
        async with self._engine.begin() as conn:
            await conn.execute(
                update(siem_outbox).where(siem_outbox.c.id.in_(ids)).values(delivered_at=at)
            )

    async def mark_failed(self, items: Sequence[OutboxItem], *, retry_at: datetime) -> None:
        async with self._engine.begin() as conn:
            for item in items:
                await conn.execute(
                    update(siem_outbox)
                    .where(siem_outbox.c.id == item.id)
                    .values(attempts=item.attempts + 1, next_attempt_at=retry_at)
                )

    async def outbox_backlog(self) -> int:
        statement = (
            select(func.count())
            .select_from(siem_outbox)
            .where(siem_outbox.c.delivered_at.is_(None))
        )
        async with self._engine.connect() as conn:
            return int((await conn.execute(statement)).scalar() or 0)

    async def purge_delivered(self, before: datetime) -> int:
        async with self._engine.begin() as conn:
            result = await conn.execute(
                delete(siem_outbox).where(
                    and_(
                        siem_outbox.c.delivered_at.is_not(None),
                        siem_outbox.c.delivered_at < _aware(before),
                    )
                )
            )
        return int(result.rowcount or 0)


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)
