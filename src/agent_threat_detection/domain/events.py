"""Normalized agent telemetry and adapters from the wire formats agents emit.

Three sources are accepted:

* native ``AgentEvent`` batches (the canonical schema, ``schemas/agent-event.schema.json``),
* agentic-core / identity-fabric audit events (hash-chained ``AuditEvent`` records),
* OpenTelemetry spans in OTLP/JSON (``ExportTraceServiceRequest``) using the GenAI
  semantic conventions plus the ``agent.*`` attributes documented in
  ``docs/architecture/agent-specification.md``.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping
from datetime import UTC, datetime
from enum import StrEnum
from functools import cached_property
from typing import Any

from agentic_core.domain.classification import DataClassification
from pydantic import BaseModel, ConfigDict, Field, field_validator

from agent_threat_detection.domain.errors import ThreatDetectionError

_SPIFFE = re.compile(r"^spiffe://[a-z0-9.\-_]{1,255}/[A-Za-z0-9.\-_/]{1,255}$")

AttributeValue = str | int | float | bool


class EventKind(StrEnum):
    TOOL_CALL = "tool_call"
    MODEL_CALL = "model_call"
    AUTHORIZATION = "authorization"
    # An event kind name, not a credential.
    TOKEN = "token"  # noqa: S105  # nosec B105
    DELEGATION = "delegation"
    DATA_TRANSFER = "data_transfer"
    CONTENT_INGEST = "content_ingest"
    LIFECYCLE = "lifecycle"


class Outcome(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    DENIED = "denied"
    REQUIRE_APPROVAL = "require_approval"


def validate_agent_uri(value: str) -> str:
    if not _SPIFFE.fullmatch(value):
        raise ValueError("agent identifiers must be SPIFFE URIs (spiffe://<domain>/<path>)")
    return value


class AgentEvent(BaseModel):
    """One observable action taken by (or on behalf of) an agent."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    event_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:\-]+$")
    agent_id: str = Field(max_length=512, description="SPIFFE ID of the acting agent")
    timestamp: datetime
    kind: EventKind
    action: str = Field(min_length=1, max_length=200, description="Tool name or scope action")
    tool: str | None = Field(default=None, max_length=200)
    resource: str | None = Field(default=None, max_length=1024)
    outcome: Outcome = Outcome.SUCCESS
    classification: DataClassification = DataClassification.INTERNAL
    bytes_out: int = Field(default=0, ge=0, le=10**13)
    destination: str | None = Field(default=None, max_length=255, description="Egress host")
    delegate: str | None = Field(default=None, max_length=512, description="Agent receiving work")
    delegation_chain: tuple[str, ...] = Field(default=(), max_length=16)
    scopes_requested: tuple[str, ...] = Field(default=(), max_length=64)
    content_excerpt: str | None = Field(
        default=None,
        max_length=8192,
        description="Content the agent ingested or sent. Scanned, never persisted.",
    )
    injection_score: float | None = Field(default=None, ge=0.0, le=1.0)
    session_id: str | None = Field(default=None, max_length=128)
    attributes: dict[str, AttributeValue] = Field(default_factory=dict, max_length=32)

    @field_validator("agent_id")
    @classmethod
    def _agent(cls, value: str) -> str:
        return validate_agent_uri(value)

    @field_validator("delegate")
    @classmethod
    def _delegate(cls, value: str | None) -> str | None:
        return None if value is None else validate_agent_uri(value)

    @field_validator("delegation_chain")
    @classmethod
    def _chain(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for item in value:
            validate_agent_uri(item)
        return value

    @field_validator("timestamp")
    @classmethod
    def _aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("timestamp must include a timezone offset")
        return value.astimezone(UTC)

    @field_validator("destination")
    @classmethod
    def _host(cls, value: str | None) -> str | None:
        return None if value is None else value.strip().lower().rstrip(".")

    @property
    def session(self) -> str:
        """Session key for sequence context; events without one share a stream."""
        return self.session_id or ""

    @property
    def subject(self) -> str:
        """The primary token for sequence modelling: the tool, else the action."""
        return self.tool or self.action

    @cached_property
    def rule_view(self) -> dict[str, Any]:
        """Primitive field values seen by detection rules, computed once per event."""
        view: dict[str, Any] = {
            name: (value.value if isinstance(value, StrEnum) else value)
            for name, value in self.__dict__.items()
            if name != "attributes"
        }
        view["classification"] = int(self.classification)
        view["hour"] = self.timestamp.hour
        view["delegation_depth"] = len(self.delegation_chain)
        return view

    def field(self, name: str) -> Any:
        """Field lookup used by detection rules; ``attributes.x`` reaches custom attributes."""
        if name.startswith("attributes."):
            return self.attributes.get(name.split(".", 1)[1])
        return self.rule_view.get(name)


class AgentEventBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    events: list[AgentEvent] = Field(min_length=1, max_length=1000)


# ----------------------------------------------------------------- audit events

_AUTHZ_OUTCOMES = {
    "allow": Outcome.SUCCESS,
    "deny": Outcome.DENIED,
    "require_approval": Outcome.REQUIRE_APPROVAL,
}
_GENERIC_OUTCOMES = {
    "success": Outcome.SUCCESS,
    "failure": Outcome.FAILURE,
    "denied": Outcome.DENIED,
}


class AuditRecord(BaseModel):
    """The subset of an agentic-core ``AuditEvent`` the detector consumes."""

    model_config = ConfigDict(extra="ignore")

    event_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:\-]+$")
    timestamp: datetime
    actor: str = Field(max_length=512)
    action: str = Field(min_length=1, max_length=200)
    resource: str = Field(max_length=1024)
    outcome: str = Field(max_length=64)
    details: dict[str, Any] = Field(default_factory=dict)


class AuditBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    events: list[AuditRecord] = Field(min_length=1, max_length=1000)


def _chain(details: Mapping[str, Any]) -> tuple[str, ...]:
    raw = details.get("chain", [])
    return tuple(str(x) for x in raw if isinstance(x, str)) if isinstance(raw, list) else ()


def from_audit(record: AuditRecord) -> AgentEvent | None:  # noqa: PLR0911
    """Map an identity-fabric / agentic-core audit record to an ``AgentEvent``.

    Returns ``None`` for records whose actor is not an agent (administrators,
    services) because the detector models agent behaviour only.
    """
    action = record.action
    details = record.details
    common: dict[str, Any] = {
        "event_id": f"audit:{record.event_id}",
        "timestamp": record.timestamp,
    }
    if action == "token.exchange":
        # The fabric records actor = delegate (the agent receiving authority)
        # and resource = the delegating subject.
        if not _SPIFFE.fullmatch(record.resource) or not _SPIFFE.fullmatch(record.actor):
            return None
        scope = details.get("scope") or " ".join(details.get("requested", []) or [])
        return AgentEvent(
            **common,
            agent_id=record.resource,
            kind=EventKind.DELEGATION,
            action="token.exchange",
            delegate=record.actor,
            outcome=_GENERIC_OUTCOMES.get(record.outcome, Outcome.FAILURE),
            scopes_requested=tuple(str(scope).split())[:64],
            attributes={"depth": int(details.get("depth", 1))},
        )
    if not _SPIFFE.fullmatch(record.actor):
        return None
    if action.startswith("token."):
        scope = details.get("scope", "")
        return AgentEvent(
            **common,
            agent_id=record.actor,
            kind=EventKind.TOKEN,
            action=action,
            outcome=_GENERIC_OUTCOMES.get(record.outcome, Outcome.FAILURE),
            scopes_requested=tuple(str(scope).split())[:64],
        )
    if action.startswith("agent."):
        return AgentEvent(
            **common,
            agent_id=record.actor,
            kind=EventKind.LIFECYCLE,
            action=action,
            outcome=_GENERIC_OUTCOMES.get(record.outcome, Outcome.FAILURE),
        )
    if record.outcome in _AUTHZ_OUTCOMES:
        classification = details.get("classification", int(DataClassification.INTERNAL))
        return AgentEvent(
            **common,
            agent_id=record.actor,
            kind=EventKind.AUTHORIZATION,
            action=action,
            resource=record.resource,
            outcome=_AUTHZ_OUTCOMES[record.outcome],
            classification=DataClassification(max(0, min(3, int(classification)))),
            delegation_chain=_chain(details)[:16],
        )
    return AgentEvent(
        **common,
        agent_id=record.actor,
        kind=EventKind.TOOL_CALL,
        action=action,
        resource=record.resource,
        outcome=_GENERIC_OUTCOMES.get(record.outcome, Outcome.FAILURE),
    )


# ---------------------------------------------------------------- OTLP spans

_OPERATION_KIND = {
    "execute_tool": EventKind.TOOL_CALL,
    "chat": EventKind.MODEL_CALL,
    "text_completion": EventKind.MODEL_CALL,
    "generate_content": EventKind.MODEL_CALL,
    "embeddings": EventKind.MODEL_CALL,
    "invoke_agent": EventKind.DELEGATION,
    "retrieve": EventKind.CONTENT_INGEST,
    "data_transfer": EventKind.DATA_TRANSFER,
    "authorize": EventKind.AUTHORIZATION,
}


def _attr_value(value: Mapping[str, Any]) -> AttributeValue | list[AttributeValue] | None:
    if "stringValue" in value:
        return str(value["stringValue"])
    if "intValue" in value:
        return int(value["intValue"])
    if "doubleValue" in value:
        return float(value["doubleValue"])
    if "boolValue" in value:
        return bool(value["boolValue"])
    if "arrayValue" in value:
        items: list[AttributeValue] = []
        for item in value["arrayValue"].get("values", []):
            parsed = _attr_value(item)
            if parsed is not None and not isinstance(parsed, list):
                items.append(parsed)
        return items
    return None


def _attributes(raw: Any) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if not isinstance(raw, list):
        return out
    for entry in raw:
        if isinstance(entry, dict) and isinstance(entry.get("key"), str):
            value = entry.get("value")
            if isinstance(value, dict):
                out[entry["key"]] = _attr_value(value)
    return out


def iter_otlp_spans(document: Mapping[str, Any]) -> Iterator[dict[str, Any]]:
    """Yield spans with resource attributes merged under span attributes."""
    for resource_spans in document.get("resourceSpans", []) or []:
        if not isinstance(resource_spans, dict):
            continue
        resource = _attributes((resource_spans.get("resource") or {}).get("attributes"))
        for scope_spans in resource_spans.get("scopeSpans", []) or []:
            if not isinstance(scope_spans, dict):
                continue
            for span in scope_spans.get("spans", []) or []:
                if isinstance(span, dict):
                    yield {
                        **span,
                        "_attributes": {**resource, **_attributes(span.get("attributes"))},
                    }


def from_otlp_span(span: Mapping[str, Any]) -> AgentEvent | None:
    """Map one OTLP span to an ``AgentEvent``; spans without an agent identity are skipped."""
    attrs: dict[str, Any] = span["_attributes"]
    agent_id = attrs.get("agent.id") or attrs.get("gen_ai.agent.id")
    if not isinstance(agent_id, str) or not _SPIFFE.fullmatch(agent_id):
        return None
    operation = str(attrs.get("gen_ai.operation.name", ""))
    kind = _OPERATION_KIND.get(operation)
    if kind is None:
        return None
    start = int(str(span.get("startTimeUnixNano", "0")) or 0)
    if start <= 0:
        raise ThreatDetectionError("span startTimeUnixNano is required")
    status = span.get("status") or {}
    code = status.get("code") if isinstance(status, dict) else None
    outcome = Outcome.FAILURE if code in (2, "STATUS_CODE_ERROR") else Outcome.SUCCESS
    if kind is EventKind.AUTHORIZATION:
        decision = str(attrs.get("agent.authorization.decision", "allow"))
        outcome = _AUTHZ_OUTCOMES.get(decision, Outcome.DENIED)
    tool = attrs.get("gen_ai.tool.name")
    action = str(attrs.get("agent.action") or tool or operation)
    chain = attrs.get("agent.delegation.chain")
    scopes = attrs.get("agent.scopes.requested")
    trace_id = str(span.get("traceId", ""))
    span_id = str(span.get("spanId", ""))
    if not span_id:
        raise ThreatDetectionError("span spanId is required")
    return AgentEvent(
        event_id=f"otel:{trace_id}:{span_id}"[:128],
        agent_id=agent_id,
        timestamp=datetime.fromtimestamp(start / 1e9, tz=UTC),
        kind=kind,
        action=action[:200],
        tool=str(tool)[:200] if tool else None,
        resource=str(attrs["agent.resource"])[:1024] if attrs.get("agent.resource") else None,
        outcome=outcome,
        classification=DataClassification(
            max(0, min(3, int(attrs.get("agent.data.classification", 1))))
        ),
        bytes_out=max(0, int(attrs.get("agent.egress.bytes", 0))),
        destination=str(attrs["server.address"]) if attrs.get("server.address") else None,
        delegate=(
            str(attrs["agent.delegate.id"])
            if isinstance(attrs.get("agent.delegate.id"), str)
            else None
        ),
        delegation_chain=tuple(str(x) for x in chain)[:16] if isinstance(chain, list) else (),
        scopes_requested=tuple(str(x) for x in scopes)[:64] if isinstance(scopes, list) else (),
        content_excerpt=(
            str(attrs["agent.content.excerpt"])[:8192]
            if attrs.get("agent.content.excerpt")
            else None
        ),
        injection_score=(
            float(attrs["agent.injection.score"])
            if isinstance(attrs.get("agent.injection.score"), int | float)
            else None
        ),
        session_id=(
            str(attrs["gen_ai.conversation.id"])[:128]
            if attrs.get("gen_ai.conversation.id")
            else None
        ),
    )
