"""Threat detection use cases.

Telemetry -> Behavioural baseline -> Detection -> Containment:

``ingest`` groups a batch by agent, processes each agent's events in time
order under a per-agent lock, deduplicates signals into alerts, and commits
the profile, alerts, SIEM findings and processed event ids atomically.
High and critical alerts are then handed to containment. Analysts
acknowledge and resolve alerts; a false-positive verdict suppresses the alert
key, folds its evidence into the baseline and rolls back any containment.
"""

from __future__ import annotations

import asyncio
import weakref
from collections import defaultdict
from collections.abc import Sequence
from datetime import timedelta
from enum import StrEnum
from typing import Any

from agentic_core.audit import AuditLog
from agentic_core.observability import correlation_id
from pydantic import BaseModel, ConfigDict, Field

from agent_threat_detection.application.containment import ContainmentService
from agent_threat_detection.detection.baseline import AgentProfile, missing_mass
from agent_threat_detection.detection.pipeline import DetectionPipeline, suppression_expiry
from agent_threat_detection.domain.errors import ConflictError, InvalidStateError, NotFoundError
from agent_threat_detection.domain.events import AgentEvent
from agent_threat_detection.domain.findings import (
    Alert,
    AlertStatus,
    ContainmentAction,
    ContainmentStatus,
    Severity,
)
from agent_threat_detection.domain.ports import Clock
from agent_threat_detection.infrastructure.database import (
    AlertQuery,
    AlertWrite,
    ThreatStore,
)
from agent_threat_detection.infrastructure.siem import Activity, encode

MAX_CONFLICT_RETRIES = 3


class IngestResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    accepted: int
    duplicates: int
    skipped: int = Field(default=0, description="Records that carried no agent activity")
    signals: int
    alerts_opened: list[str] = Field(default_factory=list)
    alerts_updated: list[str] = Field(default_factory=list)
    containment: list[str] = Field(default_factory=list)


class Resolution(StrEnum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"


class AgentRiskView(BaseModel):
    """What an analyst needs to judge an agent's current state."""

    model_config = ConfigDict(frozen=True)

    agent_id: str
    baseline_mature: bool
    events_seen: int
    events_learned: int
    risk: float
    tools: int
    destinations: int
    delegates: int
    max_classification: int
    max_delegation_depth: int
    tool_novelty_mass: float
    top_tools: list[tuple[str, int]]
    open_alerts: int
    containment: ContainmentAction | None


class _AgentLocks:
    def __init__(self) -> None:
        self._locks: weakref.WeakValueDictionary[str, asyncio.Lock] = weakref.WeakValueDictionary()

    def get(self, agent_id: str) -> asyncio.Lock:
        lock = self._locks.get(agent_id)
        if lock is None:
            lock = asyncio.Lock()
            self._locks[agent_id] = lock
        return lock


class _AgentOutcome(BaseModel):
    accepted: int = 0
    duplicates: int = 0
    signals: int = 0
    opened: list[Alert] = Field(default_factory=list)
    updated: list[Alert] = Field(default_factory=list)


class ThreatDetectionService:
    def __init__(
        self,
        *,
        store: ThreatStore,
        pipeline: DetectionPipeline,
        containment: ContainmentService,
        audit: AuditLog,
        clock: Clock,
    ) -> None:
        self._store = store
        self._pipeline = pipeline
        self._containment = containment
        self._audit = audit
        self._clock = clock
        self._locks = _AgentLocks()

    @property
    def pipeline(self) -> DetectionPipeline:
        return self._pipeline

    @property
    def containment(self) -> ContainmentService:
        return self._containment

    @property
    def store(self) -> ThreatStore:
        return self._store

    # ------------------------------------------------------------------ ingest

    async def ingest(
        self, events: Sequence[AgentEvent], *, source: str, actor: str
    ) -> IngestResult:
        by_agent: dict[str, list[AgentEvent]] = defaultdict(list)
        for event in events:
            by_agent[event.agent_id].append(event)
        totals = _AgentOutcome()
        for agent_id in sorted(by_agent):
            batch = sorted(by_agent[agent_id], key=lambda e: (e.timestamp, e.event_id))
            async with self._locks.get(agent_id):
                outcome = await self._ingest_agent(agent_id, batch)
            totals.accepted += outcome.accepted
            totals.duplicates += outcome.duplicates
            totals.signals += outcome.signals
            totals.opened.extend(outcome.opened)
            totals.updated.extend(outcome.updated)

        contained: list[str] = []
        for alert in [*totals.opened, *totals.updated]:
            if alert.severity >= Severity.HIGH and alert.containment_id is None:
                action = await self._containment.consider(alert)
                if action is not None:
                    contained.append(action.containment_id)
        await self._record(
            actor,
            "telemetry.ingest",
            source,
            "success",
            {
                "accepted": totals.accepted,
                "duplicates": totals.duplicates,
                "signals": totals.signals,
                "alerts_opened": [a.alert_id for a in totals.opened],
                "alerts_updated": [a.alert_id for a in totals.updated],
            },
        )
        return IngestResult(
            accepted=totals.accepted,
            duplicates=totals.duplicates,
            signals=totals.signals,
            alerts_opened=[a.alert_id for a in totals.opened],
            alerts_updated=[a.alert_id for a in totals.updated],
            containment=sorted(set(contained)),
        )

    async def _ingest_agent(self, agent_id: str, events: list[AgentEvent]) -> _AgentOutcome:
        for attempt in range(MAX_CONFLICT_RETRIES):
            try:
                return await self._process_agent(agent_id, events)
            except ConflictError:
                # Another replica committed this agent first: reload and replay.
                if attempt == MAX_CONFLICT_RETRIES - 1:
                    raise
        raise AssertionError("unreachable")  # pragma: no cover

    async def _process_agent(self, agent_id: str, events: list[AgentEvent]) -> _AgentOutcome:
        cfg = self._pipeline.config
        now = self._clock.now()
        profile = await self._store.get_profile(agent_id)
        if profile is None:
            profile = self._pipeline.new_profile(agent_id, events[0].timestamp)
        expected_version = profile.version
        already = await self._store.processed(e.event_id for e in events)
        outcome = _AgentOutcome()
        pending: dict[str, tuple[Alert, int | None]] = {}
        accepted_ids: list[str] = []
        for event in events:
            if event.event_id in already:
                outcome.duplicates += 1
                continue
            already.add(event.event_id)
            accepted_ids.append(event.event_id)
            outcome.accepted += 1
            result = self._pipeline.process(profile, event)
            outcome.signals += len(result.signals)
            for signal in result.alertable:
                key = signal.dedup_key()
                if key in pending:
                    alert, previous = pending[key]
                    pending[key] = (alert.merge(signal, now=now), previous)
                    continue
                window_start = signal.observed_at - timedelta(seconds=cfg.dedup_window_s)
                existing = await self._store.find_open_alert(key, since=window_start)
                if existing is None:
                    pending[key] = (Alert.open_from(signal, now=now), None)
                else:
                    pending[key] = (existing.merge(signal, now=now), existing.version)

        writes = [AlertWrite(alert, previous) for alert, previous in pending.values()]
        outbox = [
            encode(w.alert, Activity.CREATE if w.previous_version is None else Activity.UPDATE)
            for w in writes
        ]
        await self._store.commit_batch(
            profile=profile,
            expected_version=expected_version,
            alerts_to_write=writes,
            outbox=outbox,
            event_ids=accepted_ids,
            now=now,
        )
        for write in writes:
            target = outcome.opened if write.previous_version is None else outcome.updated
            target.append(write.alert)
            await self._record(
                "agent-threat-detection",
                "alert.open" if write.previous_version is None else "alert.update",
                write.alert.agent_id,
                "success",
                {
                    "alert_id": write.alert.alert_id,
                    "detector": write.alert.detector,
                    "rule_id": write.alert.rule_id,
                    "severity": write.alert.severity.label,
                    "count": write.alert.count,
                },
            )
        return outcome

    # ------------------------------------------------------------------ alerts

    async def list_alerts(self, query: AlertQuery) -> Sequence[Alert]:
        return await self._store.list_alerts(query)

    async def get_alert(self, alert_id: str) -> Alert:
        return await self._store.get_alert(alert_id)

    async def acknowledge(self, alert_id: str, *, analyst: str, note: str) -> Alert:
        alert = await self._store.get_alert(alert_id)
        if alert.status is not AlertStatus.NEW:
            raise InvalidStateError(f"alert {alert_id} is {alert.status.value}")
        updated = alert.with_status(
            AlertStatus.ACKNOWLEDGED, now=self._clock.now(), by=analyst, note=note
        )
        await self._store.save_alert(
            AlertWrite(updated, alert.version),
            now=self._clock.now(),
            outbox=[encode(updated, Activity.UPDATE)],
        )
        await self._record(
            analyst, "alert.acknowledge", alert.agent_id, "success", {"id": alert_id}
        )
        return updated

    async def resolve(
        self, alert_id: str, *, resolution: Resolution, analyst: str, note: str
    ) -> Alert:
        alert = await self._store.get_alert(alert_id)
        if not alert.status.open:
            raise InvalidStateError(f"alert {alert_id} is already {alert.status.value}")
        now = self._clock.now()
        status = (
            AlertStatus.FALSE_POSITIVE
            if resolution is Resolution.FALSE_POSITIVE
            else AlertStatus.RESOLVED
        )
        if resolution is Resolution.FALSE_POSITIVE:
            await self._learn_benign(alert)
            if alert.containment_id:
                action = await self._store.get_containment(alert.containment_id)
                if action.status is ContainmentStatus.EXECUTED:
                    await self._containment.rollback(
                        action.containment_id, actor=analyst, note=f"false positive: {note}"
                    )
        resolved = alert.with_status(status, now=now, by=analyst, note=note)
        await self._store.save_alert(
            AlertWrite(resolved, alert.version), now=now, outbox=[encode(resolved, Activity.CLOSE)]
        )
        await self._record(
            analyst,
            "alert.resolve",
            alert.agent_id,
            "success",
            {"id": alert_id, "resolution": resolution.value},
        )
        return resolved

    async def _learn_benign(self, alert: Alert) -> None:
        until = suppression_expiry(self._clock.now(), self._pipeline.config)
        async with self._locks.get(alert.agent_id):
            for attempt in range(MAX_CONFLICT_RETRIES):
                profile = await self._store.get_profile(alert.agent_id)
                if profile is None:
                    return
                expected = profile.version
                self._pipeline.accept_as_benign(
                    profile, alert.dedup_key, [e.evidence for e in alert.evidence], until=until
                )
                try:
                    await self._store.save_profile(profile, expected_version=expected)
                    return
                except ConflictError:
                    if attempt == MAX_CONFLICT_RETRIES - 1:
                        raise

    # ---------------------------------------------------------------- profiles

    async def agent_risk(self, agent_id: str) -> AgentRiskView:
        profile = await self._store.get_profile(agent_id)
        if profile is None:
            raise NotFoundError(f"no telemetry has been seen for {agent_id}")
        return await self._risk_view(profile)

    async def _risk_view(self, profile: AgentProfile) -> AgentRiskView:
        cfg = self._pipeline.config
        open_alerts = [
            a
            for a in await self._store.list_alerts(AlertQuery(agent_id=profile.agent_id, limit=500))
            if a.status.open
        ]
        risk = profile.decayed_risk(self._clock.now(), half_life_s=cfg.risk_half_life_s)
        top = sorted(profile.tools.items(), key=lambda kv: (-kv[1], kv[0]))[:10]
        return AgentRiskView(
            agent_id=profile.agent_id,
            baseline_mature=profile.mature(cfg),
            events_seen=profile.events_seen,
            events_learned=profile.events_learned,
            risk=round(risk, 4),
            tools=len(profile.tools),
            destinations=len(profile.destinations),
            delegates=len(profile.delegates),
            max_classification=profile.max_classification,
            max_delegation_depth=profile.max_delegation_depth,
            tool_novelty_mass=round(missing_mass(profile.tools), 4),
            top_tools=top,
            open_alerts=len(open_alerts),
            containment=await self._store.active_containment(profile.agent_id),
        )

    # ------------------------------------------------------------- containment

    async def request_containment(
        self, alert_id: str, *, requester: str, requester_kind: str, reason: str
    ) -> ContainmentAction | None:
        alert = await self._store.get_alert(alert_id)
        if not alert.status.open:
            raise InvalidStateError(f"alert {alert_id} is {alert.status.value}")
        action = await self._containment.consider(
            alert, requester_kind=requester_kind, requester=requester
        )
        await self._record(
            requester,
            "containment.request",
            alert.agent_id,
            "success" if action else "denied",
            {"alert_id": alert_id, "reason": reason[:500]},
        )
        return action

    async def _record(
        self, actor: str, action: str, resource: str, outcome: str, details: dict[str, Any]
    ) -> None:
        await self._audit.record(
            actor=actor,
            action=action,
            resource=resource,
            outcome=outcome,
            correlation_id=correlation_id(),
            details=details,
        )
