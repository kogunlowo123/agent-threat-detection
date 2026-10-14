"""MCP server (official ``mcp`` SDK, streamable HTTP) mounted at ``/mcp``.

Every request must carry an identity-fabric agent credential as a bearer
token; ``BearerContext`` rejects requests without one and exposes the token
to the tools, and each tool authorizes its own action through the same
authorizer as the HTTP API before doing anything, then records an audit event.
The transport runs stateless with JSON responses so any replica can serve
any request.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from contextvars import ContextVar

from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations
from starlette.types import ASGIApp, Receive, Scope, Send

from agent_threat_detection import __version__
from agent_threat_detection.application.service import AgentRiskView, IngestResult
from agent_threat_detection.domain.errors import UnauthorizedError
from agent_threat_detection.domain.events import AgentEvent
from agent_threat_detection.domain.findings import AlertStatus
from agent_threat_detection.integrations.agent_calls import (
    AgentCalls,
    AlertSummaryList,
    ContainmentRequestResult,
    SeverityName,
)
from agent_threat_detection.runtime.container import Container

_bearer: ContextVar[str | None] = ContextVar("mcp_bearer", default=None)


def current_bearer() -> str:
    token = _bearer.get()
    if not token:
        raise UnauthorizedError("agent bearer token required")
    return token


class BearerContext:
    """ASGI wrapper: requires ``Authorization: Bearer`` and binds it for the tools."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope["headers"]}
        authorization = headers.get("authorization", "")
        token = authorization[7:].strip() if authorization.lower().startswith("bearer ") else ""
        if not token:
            body = json.dumps(
                {"error": "unauthorized", "error_description": "agent bearer token required"}
            ).encode()
            await send(
                {
                    "type": "http.response.start",
                    "status": 401,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"www-authenticate", b"Bearer"),
                        (b"content-length", str(len(body)).encode()),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": body})
            return
        reset = _bearer.set(token)
        try:
            await self.app(scope, receive, send)
        finally:
            _bearer.reset(reset)


def build_mcp(get_container: Callable[[], Container]) -> MCPServer:
    server: MCPServer = MCPServer(
        name="agent-threat-detection",
        title="Agent Threat Detection",
        version=__version__,
        log_level="WARNING",
        instructions=(
            "Runtime threat detection for AI agents. Query alerts and an agent's risk, "
            "submit telemetry, and request containment of a compromised agent. Containment "
            "requests from agents always wait for a human approver."
        ),
    )

    def calls() -> AgentCalls:
        return AgentCalls(get_container(), channel="mcp")

    @server.tool(
        name="list_alerts",
        title="List threat alerts",
        description="Deduplicated alerts, newest first, filtered by status, agent and severity.",
        annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
    )
    async def list_alerts(
        status: AlertStatus | None = None,
        agent_id: str | None = None,
        min_severity: SeverityName = "medium",
        limit: int = 50,
    ) -> AlertSummaryList:
        return await calls().list_alerts(
            current_bearer(),
            status=status,
            agent_id=agent_id,
            min_severity=min_severity,
            limit=limit,
        )

    @server.tool(
        name="get_agent_risk",
        title="Agent risk and baseline",
        description="Behavioural baseline summary, decayed risk score and active containment.",
        annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False),
    )
    async def get_agent_risk(agent_id: str) -> AgentRiskView:
        return (await calls().triage(current_bearer(), agent_id=agent_id)).risk

    @server.tool(
        name="submit_events",
        title="Submit agent telemetry",
        description="Submit up to 1000 normalized agent events for detection.",
        annotations=ToolAnnotations(readOnlyHint=False, idempotentHint=True, openWorldHint=False),
    )
    async def submit_events(events: list[AgentEvent]) -> IngestResult:
        if len(events) > 1000:
            raise ValueError("at most 1000 events per call")
        return await calls().submit_events(current_bearer(), events=events)

    @server.tool(
        name="request_containment",
        title="Request containment of an agent",
        description=(
            "Ask for the agent behind an open alert to be suspended through the identity "
            "fabric. Policy decides; agent requests always require human approval."
        ),
        annotations=ToolAnnotations(
            readOnlyHint=False, destructiveHint=True, idempotentHint=True, openWorldHint=False
        ),
    )
    async def request_containment(alert_id: str, reason: str) -> ContainmentRequestResult:
        if not 3 <= len(reason) <= 500:
            raise ValueError("reason must be 3 to 500 characters")
        return await calls().request_containment(current_bearer(), alert_id=alert_id, reason=reason)

    return server


def mcp_asgi(server: MCPServer, *, allowed_hosts: list[str]) -> ASGIApp:
    security = TransportSecuritySettings(
        enable_dns_rebinding_protection=bool(allowed_hosts),
        allowed_hosts=allowed_hosts,
        allowed_origins=[],
    )
    app = server.streamable_http_app(
        streamable_http_path="/",
        json_response=True,
        stateless_http=True,
        transport_security=security,
    )
    return BearerContext(app)
