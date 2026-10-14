"""Use cases exposed to other agents over MCP and A2A.

Both protocols call these functions, so authorization (identity fabric or
local policy) and audit behave identically whichever protocol an agent uses.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Literal

from agentic_core.observability import correlation_id
from pydantic import BaseModel, ConfigDict, Field

from agent_threat_detection.application.service import AgentRiskView, IngestResult
from agent_threat_detection.domain.errors import ThreatDetectionError
from agent_threat_detection.domain.events import AgentEvent
from agent_threat_detection.domain.findings import (
    AlertStatus,
    AlertSummary,
    ContainmentAction,
    Severity,
)
from agent_threat_detection.infrastructure.database import AlertQuery
from agent_threat_detection.runtime.container import Container
from agent_threat_detection.security.agents import AgentPrincipal

SeverityName = Literal["informational", "low", "medium", "high", "critical"]


class AlertSummaryList(BaseModel):
    model_config = ConfigDict(frozen=True)

    alerts: list[AlertSummary]


class AgentTriage(BaseModel):
    model_config = ConfigDict(frozen=True)

    risk: AgentRiskView
    open_alerts: list[AlertSummary]


class ContainmentRequestResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    outcome: Literal["denied", "pending_approval", "executed", "failed", "attached"]
    containment: ContainmentAction | None = None
    explanation: str = Field(description="Why the request ended in this outcome")


class AgentCalls:
    def __init__(self, container: Container, *, channel: str) -> None:
        self._c = container
        self._channel = channel

    async def authorize(self, token: str, *, action: str, resource_type: str) -> AgentPrincipal:
        try:
            principal = await self._c.agents.authorize(
                token, action=action, resource_type=resource_type
            )
        except ThreatDetectionError as exc:
            self._c.metrics.authorization.labels(self._channel, exc.code).inc()
            await self._audit("unknown-agent", action, "denied", {"error": exc.code})
            raise
        self._c.metrics.authorization.labels(self._channel, "allow").inc()
        return principal

    async def _audit(
        self, actor: str, action: str, outcome: str, details: dict[str, object]
    ) -> None:
        await self._c.audit.record(
            actor=actor,
            action=f"{self._channel}.{action}",
            resource="agent-threat-detection",
            outcome=outcome,
            correlation_id=correlation_id(),
            details=details,
        )

    async def list_alerts(
        self,
        token: str,
        *,
        status: AlertStatus | None,
        agent_id: str | None,
        min_severity: SeverityName,
        limit: int,
    ) -> AlertSummaryList:
        who = await self.authorize(token, action="threat:read", resource_type="alerts")
        alerts = await self._c.service.list_alerts(
            AlertQuery(
                status=status,
                agent_id=agent_id,
                min_severity=Severity.parse(min_severity),
                limit=max(1, min(limit, 200)),
            )
        )
        await self._audit(who.subject, "list_alerts", "success", {"returned": len(alerts)})
        return AlertSummaryList(alerts=[AlertSummary.of(a) for a in alerts])

    async def triage(self, token: str, *, agent_id: str) -> AgentTriage:
        who = await self.authorize(token, action="threat:read", resource_type="profiles")
        risk = await self._c.service.agent_risk(agent_id)
        alerts = await self._c.service.list_alerts(AlertQuery(agent_id=agent_id, limit=100))
        await self._audit(who.subject, "triage", "success", {"agent_id": agent_id})
        return AgentTriage(
            risk=risk, open_alerts=[AlertSummary.of(a) for a in alerts if a.status.open]
        )

    async def submit_events(self, token: str, *, events: Sequence[AgentEvent]) -> IngestResult:
        who = await self.authorize(token, action="telemetry:write", resource_type="telemetry")
        result = await self._c.service.ingest(list(events), source=self._channel, actor=who.subject)
        self._c.metrics.events.labels(self._channel).inc(result.accepted)
        self._c.metrics.signals.labels(self._channel).inc(result.signals)
        return result

    async def request_containment(
        self, token: str, *, alert_id: str, reason: str
    ) -> ContainmentRequestResult:
        who = await self.authorize(token, action="containment:request", resource_type="alerts")
        action = await self._c.service.request_containment(
            alert_id, requester=who.subject, requester_kind="agent", reason=reason
        )
        if action is None:
            return ContainmentRequestResult(
                outcome="denied",
                explanation="containment policy does not suspend agents for this alert severity",
            )
        if action.alert_id != alert_id:
            return ContainmentRequestResult(
                outcome="attached",
                containment=action,
                explanation="the agent already has an active containment action",
            )
        outcome: Literal["pending_approval", "executed", "failed"] = (
            "executed"
            if action.status.value == "executed"
            else "failed" if action.status.value == "failed" else "pending_approval"
        )
        return ContainmentRequestResult(
            outcome=outcome,
            containment=action,
            explanation=(
                "a containment approver must approve the suspension"
                if outcome == "pending_approval"
                else f"containment {outcome}"
            ),
        )
