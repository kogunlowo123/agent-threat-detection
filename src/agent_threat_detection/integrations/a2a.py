"""A2A (Agent2Agent) surface: Agent Card and JSON-RPC ``message/send``.

Skills, chosen by ``message.metadata.skill`` or a ``skill`` key in the data part:

* ``triage-agent``: ``{"agent_id": "spiffe://..."}``; a text part containing a
  SPIFFE ID selects this skill too.
* ``ingest-telemetry``: ``{"events": [AgentEvent, ...]}``
* ``request-containment``: ``{"alert_id": "...", "reason": "..."}``

Replies are A2A ``Message`` objects with one data part.
"""

from __future__ import annotations

import json
import re
from typing import Any

from agentic_core.domain.identifiers import new_id
from pydantic import BaseModel, ValidationError

from agent_threat_detection import __version__
from agent_threat_detection.domain.errors import (
    ApprovalRequiredError,
    NotFoundError,
    ThreatDetectionError,
    UnauthorizedError,
)
from agent_threat_detection.domain.events import AgentEvent
from agent_threat_detection.integrations.agent_calls import AgentCalls
from agent_threat_detection.runtime.container import Container

PROTOCOL_VERSION = "0.3.0"
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603
UNSUPPORTED_OPERATION = -32004
AUTHORIZATION_DENIED = -32050
_SPIFFE = re.compile(r"spiffe://[a-z0-9.\-_]+/[A-Za-z0-9.\-_/]+")

SKILLS: list[dict[str, Any]] = [
    {
        "id": "triage-agent",
        "name": "Triage an agent",
        "description": (
            "Return an agent's behavioural baseline summary, decayed risk score, open alerts "
            "and active containment."
        ),
        "tags": ["security", "threat-detection", "triage"],
        "examples": ["Triage spiffe://agents.corp/agent/finance/invoice-matcher"],
        "inputModes": ["application/json", "text/plain"],
        "outputModes": ["application/json"],
    },
    {
        "id": "ingest-telemetry",
        "name": "Ingest agent telemetry",
        "description": "Run up to 1000 normalized agent events through baselining and detection.",
        "tags": ["telemetry", "detection"],
        "examples": ['{"skill": "ingest-telemetry", "events": [...]}'],
        "inputModes": ["application/json"],
        "outputModes": ["application/json"],
    },
    {
        "id": "request-containment",
        "name": "Request containment",
        "description": (
            "Ask for the agent behind an open alert to be suspended via the identity fabric. "
            "Requests from agents always wait for a human containment approver."
        ),
        "tags": ["response", "soar", "containment"],
        "examples": ['{"skill": "request-containment", "alert_id": "...", "reason": "..."}'],
        "inputModes": ["application/json"],
        "outputModes": ["application/json"],
    },
]


def agent_card(container: Container) -> dict[str, Any]:
    base = container.settings.public_base
    return {
        "protocolVersion": PROTOCOL_VERSION,
        "name": "Agent Threat Detection",
        "description": (
            "Runtime threat detection for agent ecosystems: per-agent behavioural baselines, "
            "behavioural and Sigma-style detections, OCSF findings and approval-gated "
            "containment through the agent identity fabric."
        ),
        "url": f"{base}/a2a",
        "preferredTransport": "JSONRPC",
        "version": __version__,
        "provider": {
            "organization": "kogunlowo123",
            "url": "https://github.com/kogunlowo123/agent-threat-detection",
        },
        "documentationUrl": "https://github.com/kogunlowo123/agent-threat-detection#readme",
        "capabilities": {
            "streaming": False,
            "pushNotifications": False,
            "stateTransitionHistory": False,
        },
        "defaultInputModes": ["application/json", "text/plain"],
        "defaultOutputModes": ["application/json"],
        "skills": SKILLS,
        "securitySchemes": {
            "agentCredential": {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "JWT",
                "description": "Agent credential issued by the agent identity fabric.",
            }
        },
        "security": [{"agentCredential": []}],
    }


class JsonRpcError(Exception):
    def __init__(self, code: int, message: str, data: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data


def _error(request_id: Any, exc: JsonRpcError) -> dict[str, Any]:
    error: dict[str, Any] = {"code": exc.code, "message": exc.message}
    if exc.data:
        error["data"] = exc.data
    return {"jsonrpc": "2.0", "id": request_id, "error": error}


def _select(message: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    parts = message.get("parts")
    if not isinstance(parts, list) or not parts:
        raise JsonRpcError(INVALID_PARAMS, "message.parts must be a non-empty array")
    data: dict[str, Any] = {}
    text = ""
    for part in parts:
        if not isinstance(part, dict):
            raise JsonRpcError(INVALID_PARAMS, "each part must be an object")
        kind = part.get("kind")
        if kind == "data" and isinstance(part.get("data"), dict):
            data.update(part["data"])
        elif kind == "text" and isinstance(part.get("text"), str):
            text += part["text"] + "\n"
        else:
            raise JsonRpcError(INVALID_PARAMS, f"unsupported part kind {kind!r}")
    metadata = message.get("metadata") if isinstance(message.get("metadata"), dict) else {}
    skill = str((metadata or {}).get("skill") or data.pop("skill", "") or "")
    if not skill and text:
        match = _SPIFFE.search(text)
        if match:
            return "triage-agent", {"agent_id": match.group(0)}
    if not skill:
        raise JsonRpcError(INVALID_PARAMS, "no skill selected; set metadata.skill")
    return skill, data


async def _dispatch(calls: AgentCalls, token: str, skill: str, data: dict[str, Any]) -> BaseModel:
    if skill == "triage-agent":
        agent_id = data.get("agent_id")
        if not isinstance(agent_id, str):
            raise JsonRpcError(INVALID_PARAMS, "agent_id is required")
        return await calls.triage(token, agent_id=agent_id)
    if skill == "ingest-telemetry":
        raw = data.get("events")
        if not isinstance(raw, list) or not 1 <= len(raw) <= 1000:
            raise JsonRpcError(INVALID_PARAMS, "events must be an array of 1 to 1000 events")
        try:
            events = [AgentEvent.model_validate(e) for e in raw]
        except ValidationError as exc:
            raise JsonRpcError(
                INVALID_PARAMS, "invalid event", {"errors": exc.error_count()}
            ) from exc
        return await calls.submit_events(token, events=events)
    if skill == "request-containment":
        alert_id, reason = data.get("alert_id"), data.get("reason")
        if not isinstance(alert_id, str) or not isinstance(reason, str) or len(reason) < 3:
            raise JsonRpcError(INVALID_PARAMS, "alert_id and reason (3+ characters) are required")
        return await calls.request_containment(token, alert_id=alert_id, reason=reason[:500])
    raise JsonRpcError(UNSUPPORTED_OPERATION, f"unknown skill {skill!r}")


async def handle(container: Container, token: str, raw: bytes) -> dict[str, Any]:
    """Process one JSON-RPC request body and return the JSON-RPC response object."""
    try:
        request = json.loads(raw)
    except ValueError:
        return _error(None, JsonRpcError(PARSE_ERROR, "parse error"))
    request_id = request.get("id") if isinstance(request, dict) else None
    try:
        if not isinstance(request, dict) or request.get("jsonrpc") != "2.0":
            raise JsonRpcError(INVALID_REQUEST, "not a JSON-RPC 2.0 request")
        if request.get("method") != "message/send":
            raise JsonRpcError(METHOD_NOT_FOUND, f"method {request.get('method')!r} not found")
        params = request.get("params")
        message = params.get("message") if isinstance(params, dict) else None
        if not isinstance(message, dict):
            raise JsonRpcError(INVALID_PARAMS, "params.message is required")
        skill, data = _select(message)
        result = await _dispatch(AgentCalls(container, channel="a2a"), token, skill, data)
    except JsonRpcError as exc:
        return _error(request_id, exc)
    except (UnauthorizedError, ApprovalRequiredError) as exc:
        return _error(
            request_id, JsonRpcError(AUTHORIZATION_DENIED, exc.message, {"error": exc.code})
        )
    except NotFoundError as exc:
        return _error(request_id, JsonRpcError(INVALID_PARAMS, exc.message, {"error": exc.code}))
    except ThreatDetectionError as exc:
        code = AUTHORIZATION_DENIED if exc.status == 403 else INVALID_PARAMS
        return _error(request_id, JsonRpcError(code, exc.message, {"error": exc.code}))
    context_id = message.get("contextId") if isinstance(message.get("contextId"), str) else None
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {
            "kind": "message",
            "messageId": new_id(),
            "role": "agent",
            "contextId": context_id or new_id(),
            "parts": [{"kind": "data", "data": result.model_dump(mode="json")}],
            "metadata": {"skill": skill},
        },
    }
