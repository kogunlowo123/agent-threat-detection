"""Persistence and the full ingest path against a real PostgreSQL (CI service container).

Runs when THREAT_TEST_DATABASE_URL points at PostgreSQL, e.g.
postgresql+asyncpg://atd:ci-only@localhost:5432/atd
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from agent_threat_detection.detection.baseline import AgentProfile
from agent_threat_detection.domain.errors import ConflictError
from agent_threat_detection.domain.findings import Alert
from agent_threat_detection.infrastructure.database import (
    AlertWrite,
    ThreatStore,
    create_schema,
    make_engine,
)
from agent_threat_detection.infrastructure.siem import Activity, encode
from agent_threat_detection.runtime.container import build_container
from tests.conftest import FakeLifecycle, FakeSink, agent_uri, baseline_events, event, make_settings
from tests.unit.test_siem_and_findings import signal

URL = os.environ.get("THREAT_TEST_DATABASE_URL", "")

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not URL.startswith("postgresql"), reason="PostgreSQL not configured"),
]


async def test_store_round_trip() -> None:
    engine = make_engine(URL)
    await create_schema(engine)
    await create_schema(engine)  # idempotent
    store = ThreatStore(engine)
    stamp = f"{datetime.now(UTC).timestamp():.0f}"
    agent = agent_uri(f"pg-{stamp}")
    now = datetime.now(UTC)
    profile = AgentProfile.new(agent, at=now, order=3)
    alert = Alert.open_from(signal(agent_id=agent), now=now)
    await store.commit_batch(
        profile=profile,
        expected_version=0,
        alerts_to_write=[AlertWrite(alert, None)],
        outbox=[encode(alert, Activity.CREATE)],
        event_ids=[f"pg-{stamp}-1"],
        now=now,
    )
    assert (await store.get_profile(agent)) == profile
    assert await store.processed([f"pg-{stamp}-1", "nope"]) == {f"pg-{stamp}-1"}
    since = alert.last_seen - timedelta(hours=1)
    assert await store.find_open_alert(alert.dedup_key, since=since) == alert
    with pytest.raises(ConflictError):
        await store.save_profile(AgentProfile.new(agent, at=now, order=3), expected_version=0)
    due = await store.due_outbox(now=now + timedelta(seconds=1), limit=1000)
    assert due
    await store.mark_delivered([d.id for d in due], at=now)
    assert await store.purge_delivered(now + timedelta(days=8)) >= 1
    assert await store.purge_processed(now + timedelta(days=3)) >= 1
    await engine.dispose()


async def test_ingest_path_on_postgres(tmp_path: Path) -> None:
    settings = make_settings(tmp_path, database_url=URL)
    container = await build_container(settings, lifecycle=FakeLifecycle(), sink=FakeSink())
    try:
        stamp = f"{datetime.now(UTC).timestamp():.0f}"
        agent = agent_uri(f"pg-ingest-{stamp}")
        result = await container.service.ingest(
            baseline_events(50, agent=agent), source="native", actor="ci"
        )
        assert result.accepted == 50
        attack = await container.service.ingest(
            [event(agent=agent, action="cloudtrail:StopLogging")], source="native", actor="ci"
        )
        assert attack.alerts_opened
        assert attack.containment
    finally:
        await container.aclose()
