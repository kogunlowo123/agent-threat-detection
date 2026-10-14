"""End to end over HTTP: telemetry in, alerts and containment out, analysts in the loop."""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from agent_threat_detection.api.app import create_app
from agent_threat_detection.runtime.container import Container, build_container
from agent_threat_detection.security.analysts import AnalystRole
from agent_threat_detection.security.jwks import StaticJwks
from tests.conftest import (
    START,
    FakeFabric,
    FakeIdp,
    FakeLifecycle,
    FakeSink,
    agent_headers,
    agent_uri,
    analyst_headers,
    baseline_events,
    make_settings,
)

pytestmark = pytest.mark.e2e
END = START + timedelta(seconds=400 * 45)


def as_json(events: list[Any]) -> list[dict[str, Any]]:
    return [e.model_dump(mode="json", exclude_none=True) for e in events]


def tamper_event(n: int = 1) -> dict[str, Any]:
    return {
        "event_id": f"tamper-{n}",
        "agent_id": agent_uri(),
        "timestamp": (END + timedelta(seconds=n)).isoformat(),
        "kind": "tool_call",
        "action": "cloudtrail:StopLogging",
        "tool": "aws.cloudtrail",
        "session_id": "s-attack",
    }


def test_full_detection_and_response_lifecycle(
    client: TestClient,
    agent_idp: FakeIdp,
    analyst_idp: FakeIdp,
    lifecycle: FakeLifecycle,
    sink: FakeSink,
) -> None:
    writer = agent_headers(agent_idp, scope="telemetry:write")
    for start in range(0, 400, 200):
        batch = as_json(baseline_events()[start : start + 200])
        response = client.post("/v1/events", json={"events": batch}, headers=writer)
        assert response.status_code == 200, response.text
        assert response.json()["alerts_opened"] == []

    attack = client.post("/v1/events", json={"events": [tamper_event()]}, headers=writer)
    assert attack.status_code == 200
    body = attack.json()
    assert body["containment"]
    assert lifecycle.calls[0][0] == "suspend"

    analyst = analyst_headers(analyst_idp, AnalystRole.ANALYST)
    alerts = client.get("/v1/alerts", params={"min_severity": "critical"}, headers=analyst).json()
    tamper = next(a for a in alerts["items"] if a["rule_id"] == "atd-audit-tampering")
    assert tamper["status"] == "contained"
    assert client.get(f"/v1/alerts/{tamper['alert_id']}", headers=analyst).json()["count"] == 1
    profile = client.get("/v1/profiles", params={"agent_id": agent_uri()}, headers=analyst).json()
    assert profile["baseline_mature"] is True
    assert profile["containment"]["status"] == "executed"
    rules = client.get("/v1/rules", headers=analyst).json()
    assert rules["digest"].startswith("sha256:")
    assert len(rules["items"]) >= 9
    listed = client.get("/v1/containment", params={"status": "executed"}, headers=analyst).json()
    containment_id = listed["items"][0]["containment_id"]
    assert client.get(f"/v1/containment/{containment_id}", headers=analyst).json()["automatic"]

    # An analyst cannot approve or roll back; an approver can.
    note = {"note": "suspension confirmed as justified"}
    forbidden = client.post(
        f"/v1/containment/{containment_id}/rollback", json=note, headers=analyst
    )
    assert forbidden.status_code == 403
    approver = analyst_headers(analyst_idp, AnalystRole.APPROVER, sub="carol@corp.test")
    rolled = client.post(f"/v1/containment/{containment_id}/rollback", json=note, headers=approver)
    assert rolled.json()["status"] == "rolled_back"
    assert lifecycle.calls[-1][0] == "reinstate"

    ack = client.post(f"/v1/alerts/{tamper['alert_id']}/acknowledge", json=note, headers=analyst)
    assert ack.status_code == 409  # contained alerts are past acknowledgement
    resolved = client.post(
        f"/v1/alerts/{tamper['alert_id']}/resolve",
        json={"resolution": "true_positive", "note": "agent rebuilt from a clean image"},
        headers=analyst,
    )
    assert resolved.json()["status"] == "resolved"

    # SIEM delivery happens from the outbox in the background.
    container: Container = client.app.state.container  # type: ignore[attr-defined]
    client.portal.call(container.dispatcher.dispatch_once)  # type: ignore[union-attr]
    finding_types = {f["finding_info"]["analytic"]["uid"] for f in sink.findings}
    assert "atd-audit-tampering" in finding_types
    assert {f["activity_id"] for f in sink.findings} >= {1, 2, 3}

    metrics = client.get("/metrics").text
    assert 'atd_events_ingested_total{source="native"} 401.0' in metrics
    assert "atd_open_alerts" in metrics
    assert "atd_siem_outbox_backlog" in metrics
    assert 'atd_containment_actions_total{status="rolled_back"} 1.0' in metrics


def test_audit_and_otlp_ingestion(client: TestClient, agent_idp: FakeIdp) -> None:
    writer = agent_headers(agent_idp, scope="telemetry:write")
    audit = client.post(
        "/v1/events/audit",
        json={
            "events": [
                {
                    "event_id": "fab-1",
                    "timestamp": "2026-10-14T10:00:00Z",
                    "actor": agent_uri(),
                    "action": "secrets:read",
                    "resource": "secretsmanager:prod/db",
                    "outcome": "allow",
                    "details": {},
                    "sequence": 4,
                    "hash": "ignored",
                },
                {
                    "event_id": "fab-2",
                    "timestamp": "2026-10-14T10:00:01Z",
                    "actor": "alice@corp.test",
                    "action": "agent.register",
                    "resource": agent_uri(),
                    "outcome": "success",
                },
            ]
        },
        headers=writer,
    )
    assert audit.status_code == 200, audit.text
    assert audit.json()["skipped"] == 1
    assert audit.json()["alerts_opened"]

    span = {
        "traceId": "5b8efff798038103d269b633813fc60c",
        "spanId": "eee19b7ec3c1b174",
        "startTimeUnixNano": "1760436000000000000",
        "attributes": [
            {"key": "gen_ai.operation.name", "value": {"stringValue": "execute_tool"}},
            {"key": "gen_ai.tool.name", "value": {"stringValue": "http.post"}},
            {"key": "agent.id", "value": {"stringValue": agent_uri("crawler")}},
            {"key": "server.address", "value": {"stringValue": "paste.pastebin.com"}},
        ],
    }
    bad = {**span, "spanId": "", "attributes": span["attributes"]}
    ignored = {**span, "spanId": "aaaa", "attributes": span["attributes"][1:]}
    document = {"resourceSpans": [{"scopeSpans": [{"spans": [span, bad, ignored]}]}]}
    otlp = client.post("/v1/traces", json=document, headers=writer)
    assert otlp.status_code == 200, otlp.text
    assert otlp.json()["partialSuccess"]["rejectedSpans"] == 1
    protobuf = client.post(
        "/v1/traces",
        content=b"\x0a\x00",
        headers={**writer, "Content-Type": "application/x-protobuf"},
    )
    assert protobuf.status_code == 415
    for raw in (b"{not json", b"[1, 2]"):
        response = client.post(
            "/v1/traces", content=raw, headers={**writer, "Content-Type": "application/json"}
        )
        assert response.status_code == 400
    clean = client.post("/v1/traces", json={"resourceSpans": []}, headers=writer)
    assert clean.json() == {"partialSuccess": {"rejectedSpans": 0, "errorMessage": ""}}


def test_mcp_tools(client: TestClient, agent_idp: FakeIdp) -> None:
    headers = {
        **agent_headers(agent_idp),
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
    }

    def rpc(method: str, params: dict[str, Any] | None = None, rid: int = 1) -> dict[str, Any]:
        response = client.post(
            "/mcp/",
            json={"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}},
            headers=headers,
        )
        assert response.status_code == 200, response.text
        result: dict[str, Any] = response.json()
        return result

    init = rpc(
        "initialize",
        {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "t", "version": "1"},
        },
    )
    assert init["result"]["serverInfo"]["name"] == "agent-threat-detection"
    tools = {t["name"]: t for t in rpc("tools/list")["result"]["tools"]}
    assert set(tools) == {"list_alerts", "get_agent_risk", "submit_events", "request_containment"}
    assert tools["request_containment"]["annotations"]["destructiveHint"] is True
    assert "outputSchema" in tools["list_alerts"]

    submitted = rpc(
        "tools/call", {"name": "submit_events", "arguments": {"events": [tamper_event()]}}
    )
    structured = submitted["result"]["structuredContent"]
    assert structured["accepted"] == 1
    assert structured["alerts_opened"]
    alerts = rpc("tools/call", {"name": "list_alerts", "arguments": {"min_severity": "high"}})
    alert_ids = [a["alert_id"] for a in alerts["result"]["structuredContent"]["alerts"]]
    risk = rpc("tools/call", {"name": "get_agent_risk", "arguments": {"agent_id": agent_uri()}})
    assert risk["result"]["structuredContent"]["agent_id"] == agent_uri()
    request = rpc(
        "tools/call",
        {
            "name": "request_containment",
            "arguments": {"alert_id": alert_ids[0], "reason": "agent disabled audit logging"},
        },
    )
    assert request["result"]["structuredContent"]["outcome"] in {"attached", "executed"}
    bad = rpc(
        "tools/call", {"name": "request_containment", "arguments": {"alert_id": "x", "reason": "x"}}
    )
    assert bad["result"]["isError"] is True
    too_many = rpc(
        "tools/call",
        {"name": "submit_events", "arguments": {"events": [tamper_event(i) for i in range(1001)]}},
    )
    assert too_many["result"]["isError"] is True

    read_only = {**headers, **agent_headers(agent_idp, scope="threat:read")}
    denied = client.post(
        "/mcp/",
        json={
            "jsonrpc": "2.0",
            "id": 9,
            "method": "tools/call",
            "params": {"name": "submit_events", "arguments": {"events": [tamper_event(5)]}},
        },
        headers=read_only,
    ).json()
    assert denied["result"]["isError"] is True
    unauthenticated = client.post(
        "/mcp/",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers={"Accept": headers["Accept"], "Content-Type": "application/json"},
    )
    assert unauthenticated.status_code == 401
    assert unauthenticated.headers["www-authenticate"] == "Bearer"


def test_a2a_agent_card_and_skills(client: TestClient, agent_idp: FakeIdp) -> None:
    card = client.get("/.well-known/agent-card.json").json()
    assert card["url"] == "https://threat.corp.test/a2a"
    assert {s["id"] for s in card["skills"]} == {
        "triage-agent",
        "ingest-telemetry",
        "request-containment",
    }
    assert card["securitySchemes"]["agentCredential"]["scheme"] == "bearer"
    for field in ("name", "description", "version", "capabilities", "skills"):
        assert field in card

    headers = agent_headers(agent_idp)

    def send(message: dict[str, Any], method: str = "message/send", rid: Any = 1) -> dict[str, Any]:
        response = client.post(
            "/a2a",
            json={"jsonrpc": "2.0", "id": rid, "method": method, "params": {"message": message}},
            headers=headers,
        )
        assert response.status_code == 200
        result: dict[str, Any] = response.json()
        return result

    ingest = send(
        {
            "role": "user",
            "messageId": "m1",
            "metadata": {"skill": "ingest-telemetry"},
            "parts": [{"kind": "data", "data": {"events": [tamper_event()]}}],
        }
    )
    data = ingest["result"]["parts"][0]["data"]
    assert data["accepted"] == 1
    assert ingest["result"]["metadata"]["skill"] == "ingest-telemetry"
    triage = send(
        {
            "role": "user",
            "messageId": "m2",
            "contextId": "ctx-1",
            "parts": [{"kind": "text", "text": f"Please triage {agent_uri()} now"}],
        }
    )
    assert triage["result"]["contextId"] == "ctx-1"
    open_alerts = triage["result"]["parts"][0]["data"]["open_alerts"]
    assert open_alerts
    contain = send(
        {
            "role": "user",
            "messageId": "m3",
            "parts": [
                {
                    "kind": "data",
                    "data": {
                        "skill": "request-containment",
                        "alert_id": open_alerts[0]["alert_id"],
                        "reason": "audit tampering",
                    },
                }
            ],
        }
    )
    assert contain["result"]["parts"][0]["data"]["outcome"] in {
        "attached",
        "executed",
        "pending_approval",
    }

    errors = {
        "bad-skill": send(
            {
                "role": "user",
                "messageId": "x",
                "metadata": {"skill": "dance"},
                "parts": [{"kind": "data", "data": {}}],
            }
        ),
        "no-skill": send(
            {"role": "user", "messageId": "x", "parts": [{"kind": "text", "text": "hello"}]}
        ),
        "no-parts": send({"role": "user", "messageId": "x", "parts": []}),
        "bad-part": send({"role": "user", "messageId": "x", "parts": [{"kind": "file"}]}),
        "not-object-part": send({"role": "user", "messageId": "x", "parts": ["text"]}),
        "missing-agent": send(
            {
                "role": "user",
                "messageId": "x",
                "metadata": {"skill": "triage-agent"},
                "parts": [{"kind": "data", "data": {}}],
            }
        ),
        "unknown-agent": send(
            {
                "role": "user",
                "messageId": "x",
                "metadata": {"skill": "triage-agent"},
                "parts": [{"kind": "data", "data": {"agent_id": agent_uri("nobody")}}],
            }
        ),
        "bad-events": send(
            {
                "role": "user",
                "messageId": "x",
                "metadata": {"skill": "ingest-telemetry"},
                "parts": [{"kind": "data", "data": {"events": []}}],
            }
        ),
        "invalid-event": send(
            {
                "role": "user",
                "messageId": "x",
                "metadata": {"skill": "ingest-telemetry"},
                "parts": [{"kind": "data", "data": {"events": [{"x": 1}]}}],
            }
        ),
        "bad-containment": send(
            {
                "role": "user",
                "messageId": "x",
                "metadata": {"skill": "request-containment"},
                "parts": [{"kind": "data", "data": {"alert_id": "a"}}],
            }
        ),
        "closed-alert": send(
            {
                "role": "user",
                "messageId": "x",
                "metadata": {"skill": "request-containment"},
                "parts": [{"kind": "data", "data": {"alert_id": "missing", "reason": "testing"}}],
            }
        ),
        "method": send({"role": "user"}, method="tasks/get"),
    }
    codes = {name: result["error"]["code"] for name, result in errors.items()}
    assert codes["bad-skill"] == -32004
    assert codes["method"] == -32601
    assert all(
        code == -32602 for name, code in codes.items() if name not in {"bad-skill", "method"}
    )

    raw = client.post(
        "/a2a", content=b"{oops", headers={**headers, "Content-Type": "application/json"}
    )
    assert raw.json()["error"]["code"] == -32700
    not_rpc = client.post("/a2a", json={"id": 3, "method": "message/send"}, headers=headers)
    assert not_rpc.json()["error"]["code"] == -32600
    no_message = client.post(
        "/a2a",
        json={"jsonrpc": "2.0", "id": 4, "method": "message/send", "params": {}},
        headers=headers,
    )
    assert no_message.json()["error"]["code"] == -32602
    readonly = agent_headers(agent_idp, scope="threat:read")
    forbidden = client.post(
        "/a2a",
        json={
            "jsonrpc": "2.0",
            "id": 5,
            "method": "message/send",
            "params": {
                "message": {
                    "role": "user",
                    "messageId": "x",
                    "metadata": {"skill": "ingest-telemetry"},
                    "parts": [{"kind": "data", "data": {"events": [tamper_event(9)]}}],
                }
            },
        },
        headers=readonly,
    )
    assert forbidden.json()["error"]["code"] == -32050
    assert client.post("/a2a", json={}).status_code == 401


def test_operational_endpoints_and_errors(client: TestClient, analyst_idp: FakeIdp) -> None:
    assert client.get("/healthz").json() == {"status": "ok"}
    assert client.get("/readyz").json() == {"status": "ready"}
    response = client.get("/healthz", headers={"X-Correlation-ID": "trace-123"})
    assert response.headers["x-correlation-id"] == "trace-123"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert (
        client.get("/healthz", headers={"X-Correlation-ID": "x" * 200}).headers["x-correlation-id"]
        != "x" * 200
    )
    analyst = analyst_headers(analyst_idp, AnalystRole.ANALYST)
    assert client.get("/v1/alerts", params={"status": "bogus"}, headers=analyst).status_code == 400
    assert client.get("/v1/alerts/missing", headers=analyst).status_code == 404
    invalid = client.post("/v1/events", json={"events": []}, headers={"Authorization": "Bearer x"})
    assert invalid.status_code in {401, 422}
    unauthenticated = client.get("/v1/alerts")
    assert unauthenticated.status_code == 401
    assert unauthenticated.headers["www-authenticate"] == "Bearer"
    engineer = analyst_headers(analyst_idp, AnalystRole.ENGINEER)
    assert client.get("/v1/rules", headers=engineer).status_code == 200
    assert (
        client.post("/v1/alerts/x/acknowledge", json={"note": "abc"}, headers=engineer).status_code
        == 403
    )
    wrong_body = client.post(
        "/v1/alerts/x/resolve", json={"resolution": "maybe", "note": "abc"}, headers=analyst
    )
    assert wrong_body.status_code == 422
    assert wrong_body.json()["error"] == "invalid_request"


@pytest.fixture
def fabric() -> FakeFabric:
    return FakeFabric(
        tokens={
            "collector-token": (agent_uri("otel-collector", "platform"), "telemetry:write"),
            "copilot-token": (
                agent_uri("soc-copilot", "security"),
                "threat:read containment:request",
            ),
        },
        statuses={agent_uri(): "active"},
    )


@pytest.fixture
def fabric_client(
    tmp_path: Path, fabric: FakeFabric, analyst_idp: FakeIdp, sink: FakeSink
) -> Iterator[TestClient]:
    secret = tmp_path / "fabric-secret"
    secret.write_text("client-secret", encoding="utf-8")
    settings = make_settings(
        tmp_path,
        fabric_url="https://fabric.corp.test",
        fabric_token_url="https://fabric.corp.test/idp/token",
        fabric_client_id="agent-threat-detection",
        fabric_client_secret_file=secret,
        agent_jwks_url=None,
    )

    async def factory() -> Container:
        return await build_container(
            settings,
            analyst_resolver=StaticJwks(analyst_idp.jwks()),
            sink=sink,
            http=fabric.client(),
        )

    with TestClient(create_app(factory)) as test_client:
        yield test_client


def test_fabric_mode_authorizes_inbound_calls_and_suspends_through_the_fabric(
    fabric_client: TestClient, fabric: FakeFabric
) -> None:
    collector = {"Authorization": "Bearer collector-token"}
    result = fabric_client.post("/v1/events", json={"events": [tamper_event()]}, headers=collector)
    assert result.status_code == 200, result.text
    assert fabric.statuses[agent_uri()] == "suspended"
    suspend = next(r for r in fabric.requests if r.url.path == "/v1/suspend")
    assert suspend.url.params["agent_uri"] == agent_uri()
    assert "Agent disables or deletes audit logging" in json.loads(suspend.content)["reason"]

    copilot = {"Authorization": "Bearer copilot-token"}
    denied = fabric_client.post("/v1/events", json={"events": [tamper_event(2)]}, headers=copilot)
    assert denied.status_code == 403
    revoked = fabric_client.post(
        "/v1/events", json={"events": [tamper_event(3)]}, headers={"Authorization": "Bearer gone"}
    )
    assert revoked.status_code == 401
    triage = fabric_client.post(
        "/a2a",
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "message/send",
            "params": {
                "message": {
                    "role": "user",
                    "messageId": "m",
                    "parts": [{"kind": "text", "text": f"triage {agent_uri()}"}],
                }
            },
        },
        headers=copilot,
    ).json()
    assert triage["result"]["parts"][0]["data"]["risk"]["containment"]["status"] == "executed"
    fabric.down = True
    unavailable = fabric_client.post(
        "/v1/events",
        json={"events": [tamper_event(4)]},
        headers={"Authorization": "Bearer new-token"},
    )
    assert unavailable.status_code == 503
