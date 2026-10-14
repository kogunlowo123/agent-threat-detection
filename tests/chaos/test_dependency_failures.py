"""Fault injection: the detector keeps detecting, fails closed on authorization, and never
loses findings when its dependencies break."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from agent_threat_detection.domain.findings import ContainmentStatus
from agent_threat_detection.infrastructure.database import make_engine
from agent_threat_detection.runtime.container import Container
from tests.conftest import FakeIdp, FakeLifecycle, FakeSink, agent_headers, agent_uri, event

pytestmark = pytest.mark.chaos


def test_database_outage_flips_readiness(client: TestClient) -> None:
    container = client.app.state.container  # type: ignore[attr-defined]
    assert client.get("/readyz").status_code == 200
    healthy = container.engine
    container.engine = make_engine("sqlite+aiosqlite:////nonexistent/dir/db.sqlite")
    try:
        assert client.get("/readyz").status_code == 503
        assert client.get("/healthz").status_code == 200  # liveness unaffected
    finally:
        container.engine = healthy


def test_metrics_scrape_survives_database_outage(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    container = client.app.state.container  # type: ignore[attr-defined]

    async def down() -> dict[int, int]:
        raise OSError("database down")

    monkeypatch.setattr(container.store, "open_alert_counts", down)
    assert client.get("/metrics").status_code == 200


async def test_siem_outage_keeps_findings_in_the_outbox(
    container: Container, sink: FakeSink
) -> None:
    sink.fail = True
    await container.service.ingest(
        [event(action="cloudtrail:StopLogging")], source="native", actor="c"
    )
    assert await container.dispatcher.dispatch_once() == 0
    backlog = await container.store.outbox_backlog()
    assert backlog >= 1
    sink.fail = False
    container.clock.advance(60)  # type: ignore[attr-defined]
    delivered = await container.dispatcher.dispatch_once()
    assert delivered == backlog
    assert await container.store.outbox_backlog() == 0


async def test_fabric_outage_records_failed_containment_for_retry(
    container: Container, lifecycle: FakeLifecycle
) -> None:
    lifecycle.fail = True
    result = await container.service.ingest(
        [event(action="cloudtrail:StopLogging")], source="native", actor="c"
    )
    action = await container.store.get_containment(result.containment[0])
    assert action.status is ContainmentStatus.FAILED
    assert "unreachable" in (action.error or "")
    alert = await container.service.get_alert(action.alert_id)
    assert alert.status.value == "new"  # not marked contained when containment failed
    lifecycle.fail = False
    retried = await container.service.containment.approve(
        action.containment_id, approver="oncall@corp.test", note="retry after fabric recovery"
    )
    assert retried.status is ContainmentStatus.EXECUTED


async def test_audit_sink_failure_fails_the_request(container: Container) -> None:
    """If evidence cannot be written the ingest call errors instead of silently succeeding."""

    async def broken(_: object) -> None:
        raise OSError("disk full")

    container.audit._sink.append = broken  # type: ignore[method-assign]
    with pytest.raises(OSError, match="disk full"):
        await container.service.ingest([event()], source="native", actor="c")


def test_agent_jwks_unreachable_fails_closed(client: TestClient, agent_idp: FakeIdp) -> None:
    rotated = FakeIdp(agent_idp.issuer, kid="unpublished-kid")
    body = {
        "events": [
            {
                "event_id": "c1",
                "agent_id": agent_uri(),
                "timestamp": "2026-10-14T10:00:00Z",
                "kind": "tool_call",
                "action": "x",
            }
        ]
    }
    response = client.post(
        "/v1/events", json=body, headers=agent_headers(rotated, scope="telemetry:write")
    )
    assert response.status_code == 401
