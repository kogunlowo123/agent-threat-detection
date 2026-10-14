"""Telemetry normalization: native events, audit records and OTLP spans."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from pydantic import ValidationError

from agent_threat_detection.domain.errors import ThreatDetectionError
from agent_threat_detection.domain.events import (
    AgentEvent,
    AuditRecord,
    EventKind,
    Outcome,
    from_audit,
    from_otlp_span,
    iter_otlp_spans,
)
from tests.conftest import agent_uri, event


def test_event_validation_and_field_lookup() -> None:
    e = event(
        EventKind.DATA_TRANSFER,
        action="http.post",
        destination="API.Corp.Internal.",
        bytes_out=10,
        delegation_chain=(agent_uri("a"), agent_uri("b")),
        attributes={"approved_runtime": True},
        classification=2,
    )
    assert e.destination == "api.corp.internal"
    assert e.field("classification") == 2
    assert e.field("hour") == 9
    assert e.field("delegation_depth") == 2
    assert e.field("kind") == "data_transfer"
    assert e.field("attributes.approved_runtime") is True
    assert e.field("attributes.missing") is None
    assert e.field("no_such_field") is None
    assert e.subject == "http.post"
    assert e.session == ""


@pytest.mark.parametrize(
    "bad",
    [
        {"agent_id": "agent-without-spiffe"},
        {"timestamp": datetime(2026, 1, 1)},  # naive timestamp
        {"delegate": "https://not-an-agent"},
        {"delegation_chain": ("nope",)},
        {"event_id": "has spaces"},
        {"injection_score": 1.5},
        {"unknown": 1},
    ],
)
def test_event_rejects_invalid_input(bad: dict[str, Any]) -> None:
    base = {
        "event_id": "e1",
        "agent_id": agent_uri(),
        "timestamp": "2026-10-14T10:00:00Z",
        "kind": "tool_call",
        "action": "x",
    }
    with pytest.raises(ValidationError):
        AgentEvent.model_validate(base | bad)


def _audit(**overrides: Any) -> AuditRecord:
    data: dict[str, Any] = {
        "event_id": "a1",
        "timestamp": "2026-10-14T10:00:00Z",
        "actor": agent_uri(),
        "action": "fhir:read",
        "resource": "Patient:1",
        "outcome": "allow",
        "details": {"chain": [agent_uri("orchestrator")], "classification": 3},
    }
    data.update(overrides)
    return AuditRecord.model_validate(data)


def test_audit_authorization_decisions() -> None:
    allowed = from_audit(_audit())
    assert allowed is not None
    assert allowed.kind is EventKind.AUTHORIZATION
    assert allowed.outcome is Outcome.SUCCESS
    assert allowed.classification == 3
    assert allowed.delegation_chain == (agent_uri("orchestrator"),)
    denied = from_audit(_audit(outcome="deny"))
    assert denied is not None
    assert denied.outcome is Outcome.DENIED
    pending = from_audit(_audit(outcome="require_approval", details={}))
    assert pending is not None
    assert pending.outcome is Outcome.REQUIRE_APPROVAL


def test_audit_token_exchange_becomes_delegation_by_the_subject() -> None:
    subject, actor = agent_uri("orchestrator"), agent_uri("scheduler")
    mapped = from_audit(
        _audit(
            action="token.exchange",
            actor=actor,
            resource=subject,
            outcome="success",
            details={"scope": "scheduling:read fhir:read:*", "depth": 2},
        )
    )
    assert mapped is not None
    assert mapped.agent_id == subject
    assert mapped.delegate == actor
    assert mapped.kind is EventKind.DELEGATION
    assert mapped.scopes_requested == ("scheduling:read", "fhir:read:*")
    denied = from_audit(
        _audit(
            action="token.exchange",
            actor=actor,
            resource=subject,
            outcome="denied",
            details={"requested": ["admin:*"]},
        )
    )
    assert denied is not None
    assert denied.outcome is Outcome.DENIED
    assert denied.scopes_requested == ("admin:*",)
    assert from_audit(_audit(action="token.exchange", resource="not-an-agent")) is None


def test_audit_other_actions() -> None:
    issued = from_audit(_audit(action="token.issue", outcome="success", details={"scope": "a b"}))
    assert issued is not None
    assert issued.kind is EventKind.TOKEN
    assert issued.scopes_requested == ("a", "b")
    lifecycle = from_audit(_audit(action="agent.attest", outcome="failure"))
    assert lifecycle is not None
    assert lifecycle.kind is EventKind.LIFECYCLE
    assert lifecycle.outcome is Outcome.FAILURE
    tool = from_audit(_audit(action="crm.update", outcome="success"))
    assert tool is not None
    assert tool.kind is EventKind.TOOL_CALL
    odd = from_audit(_audit(action="crm.update", outcome="weird"))
    assert odd is not None
    assert odd.outcome is Outcome.FAILURE
    assert from_audit(_audit(actor="alice@corp.test")) is None


def _span(attrs: dict[str, Any], **span: Any) -> dict[str, Any]:
    def value(v: Any) -> dict[str, Any]:
        if isinstance(v, bool):
            return {"boolValue": v}
        if isinstance(v, int):
            return {"intValue": str(v)}
        if isinstance(v, float):
            return {"doubleValue": v}
        if isinstance(v, list):
            return {"arrayValue": {"values": [value(x) for x in v]}}
        return {"stringValue": v}

    body = {
        "traceId": "5b8efff798038103d269b633813fc60c",
        "spanId": "eee19b7ec3c1b174",
        "name": "op",
        "startTimeUnixNano": "1760436000000000000",
        "attributes": [{"key": k, "value": value(v)} for k, v in attrs.items()],
    }
    body.update(span)
    return {
        "resourceSpans": [
            {
                "resource": {
                    "attributes": [{"key": "agent.id", "value": {"stringValue": agent_uri()}}]
                },
                "scopeSpans": [{"spans": [body, "not-a-span"]}, "bad-scope"],
            },
            "bad-resource",
        ]
    }


def test_otlp_tool_span() -> None:
    doc = _span(
        {
            "gen_ai.operation.name": "execute_tool",
            "gen_ai.tool.name": "http.post",
            "server.address": "Erp-Api.corp.internal",
            "agent.egress.bytes": 1234,
            "agent.data.classification": 2,
            "agent.delegation.chain": [agent_uri("orchestrator")],
            "agent.scopes.requested": ["erp:write"],
            "agent.content.excerpt": "payload",
            "agent.injection.score": 0.25,
            "gen_ai.conversation.id": "conv-1",
            "agent.resource": "vendor:42",
            "agent.flag": True,
            "agent.ratio": 0.5,
            "agent.weird": {"kvlistValue": {}},
        },
        status={"code": 2},
    )
    spans = list(iter_otlp_spans(doc))
    assert len(spans) == 1
    mapped = from_otlp_span(spans[0])
    assert mapped is not None
    assert mapped.kind is EventKind.TOOL_CALL
    assert mapped.outcome is Outcome.FAILURE
    assert mapped.destination == "erp-api.corp.internal"
    assert mapped.bytes_out == 1234
    assert mapped.classification == 2
    assert mapped.session_id == "conv-1"
    assert mapped.injection_score == 0.25
    assert mapped.timestamp == datetime(2025, 10, 14, 10, 0, tzinfo=UTC)
    assert mapped.event_id.startswith("otel:5b8efff7")


def test_otlp_authorization_and_skips() -> None:
    authz = from_otlp_span(
        next(
            iter_otlp_spans(
                _span(
                    {"gen_ai.operation.name": "authorize", "agent.authorization.decision": "deny"}
                )
            )
        )
    )
    assert authz is not None
    assert authz.outcome is Outcome.DENIED
    assert (
        from_otlp_span(next(iter_otlp_spans(_span({"gen_ai.operation.name": "unknown_op"}))))
        is None
    )
    no_agent = _span({"gen_ai.operation.name": "chat"})
    no_agent["resourceSpans"][0]["resource"] = {}
    assert from_otlp_span(next(iter_otlp_spans(no_agent))) is None
    assert list(iter_otlp_spans({"resourceSpans": None})) == []


def test_otlp_missing_required_fields() -> None:
    with pytest.raises(ThreatDetectionError, match="startTimeUnixNano"):
        from_otlp_span(
            next(iter_otlp_spans(_span({"gen_ai.operation.name": "chat"}, startTimeUnixNano="0")))
        )
    with pytest.raises(ThreatDetectionError, match="spanId"):
        from_otlp_span(next(iter_otlp_spans(_span({"gen_ai.operation.name": "chat"}, spanId=""))))
