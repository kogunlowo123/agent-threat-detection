"""SOAR containment: suspend an agent through the identity fabric, behind policy and approval.

Flow for every high or critical alert:

1. Evaluate ``policies/containment.yaml`` (agentic-core PolicyEngine) with the
   alert's severity, confidence and detector, whether the agent is protected
   and whether automatic containment is enabled.
2. ``deny``: nothing happens beyond the audit record.
   ``require_approval``: a pending action waits for a containment approver.
   ``allow``: the agent is suspended immediately (critical, high confidence).
3. Execution calls ``POST /v1/suspend`` on the fabric, which invalidates every
   outstanding credential of the agent through its credential epoch.
4. Any executed action can be rolled back (``POST /v1/reinstate``); marking
   the alert a false positive rolls back automatically.

One active action exists per agent; further alerts attach to it.
"""

from __future__ import annotations

import fnmatch
from collections.abc import Sequence

from agentic_core.audit import AuditLog
from agentic_core.domain.classification import Decision, RiskLevel
from agentic_core.observability import correlation_id, get_logger
from agentic_core.policy import PolicyDecision, PolicyEngine, PolicyRequest, Resource, Subject

from agent_threat_detection.domain.errors import (
    DependencyUnavailableError,
    InvalidStateError,
    ThreatDetectionError,
)
from agent_threat_detection.domain.findings import (
    Alert,
    AlertStatus,
    ContainmentAction,
    ContainmentStatus,
    Severity,
)
from agent_threat_detection.domain.ports import AgentLifecycle, Clock
from agent_threat_detection.infrastructure.database import AlertWrite, ThreatStore
from agent_threat_detection.infrastructure.siem import Activity, encode

SERVICE_IDENTITY = "agent-threat-detection"
log = get_logger("agent_threat_detection.containment")

_RISK = {
    Severity.INFORMATIONAL: RiskLevel.LOW,
    Severity.LOW: RiskLevel.LOW,
    Severity.MEDIUM: RiskLevel.MODERATE,
    Severity.HIGH: RiskLevel.HIGH,
    Severity.CRITICAL: RiskLevel.CRITICAL,
}


class ContainmentService:
    def __init__(
        self,
        *,
        store: ThreatStore,
        policy: PolicyEngine,
        lifecycle: AgentLifecycle | None,
        audit: AuditLog,
        clock: Clock,
        protected_agents: Sequence[str],
        auto_containment: bool,
    ) -> None:
        self._store = store
        self._policy = policy
        self._lifecycle = lifecycle
        self._audit = audit
        self._clock = clock
        self._protected = tuple(protected_agents)
        self._auto = auto_containment

    @property
    def policy(self) -> PolicyEngine:
        return self._policy

    def is_protected(self, agent_id: str) -> bool:
        return any(fnmatch.fnmatchcase(agent_id, pattern) for pattern in self._protected)

    def evaluate(self, alert: Alert, *, requester_kind: str, requester: str) -> PolicyDecision:
        return self._policy.evaluate(
            PolicyRequest(
                subject=Subject(id=requester, kind=requester_kind),
                action="containment:suspend",
                resource=Resource(
                    type="agent",
                    id=alert.agent_id,
                    attributes={
                        "severity": int(alert.severity),
                        "score": alert.score,
                        "detector": alert.detector,
                        "protected": self.is_protected(alert.agent_id),
                    },
                ),
                risk=_RISK[alert.severity],
                environment={"auto_containment": self._auto},
            )
        )

    async def consider(
        self, alert: Alert, *, requester_kind: str = "service", requester: str = SERVICE_IDENTITY
    ) -> ContainmentAction | None:
        """Decide what containment, if any, an alert warrants and act on the decision."""
        existing = await self._store.active_containment(alert.agent_id)
        if existing is not None:
            await self._link(alert, existing)
            return existing
        decision = self.evaluate(alert, requester_kind=requester_kind, requester=requester)
        await self._record(
            requester,
            "containment.decide",
            alert.agent_id,
            decision.decision.value,
            {
                "alert_id": alert.alert_id,
                "rules": list(decision.matched_rules),
                "policy_digest": decision.policy_digest,
            },
        )
        if decision.decision is Decision.DENY:
            return None
        now = self._clock.now()
        action = ContainmentAction(
            agent_id=alert.agent_id,
            alert_id=alert.alert_id,
            status=ContainmentStatus.PENDING_APPROVAL,
            automatic=decision.decision is Decision.ALLOW,
            decision=decision.decision,
            matched_rules=decision.matched_rules,
            policy_version=decision.policy_version,
            policy_digest=decision.policy_digest,
            reason=f"{alert.title} (alert {alert.alert_id}, severity {alert.severity.label})",
            requested_by=requester,
            created_at=now,
            updated_at=now,
        )
        await self._store.add_containment(action)
        if action.automatic:
            action = await self._execute(action, actor=SERVICE_IDENTITY)
        await self._link(alert, action)
        return action

    async def approve(self, containment_id: str, *, approver: str, note: str) -> ContainmentAction:
        action = await self._store.get_containment(containment_id)
        if action.status not in {ContainmentStatus.PENDING_APPROVAL, ContainmentStatus.FAILED}:
            raise InvalidStateError(f"containment {containment_id} is {action.status.value}")
        if approver == action.requested_by:
            raise InvalidStateError("the requester cannot approve their own containment request")
        approved = action.evolve(now=self._clock.now(), approved_by=approver)
        await self._store.update_containment(approved, previous_version=action.version)
        await self._record(
            approver, "containment.approve", action.agent_id, "success", {"note": note[:500]}
        )
        executed = await self._execute(approved, actor=approver)
        await self._sync_alert(executed)
        return executed

    async def reject(self, containment_id: str, *, approver: str, note: str) -> ContainmentAction:
        action = await self._store.get_containment(containment_id)
        if action.status is not ContainmentStatus.PENDING_APPROVAL:
            raise InvalidStateError(f"containment {containment_id} is {action.status.value}")
        rejected = action.evolve(
            now=self._clock.now(), status=ContainmentStatus.REJECTED, rejected_by=approver
        )
        await self._store.update_containment(rejected, previous_version=action.version)
        await self._record(
            approver, "containment.reject", action.agent_id, "success", {"note": note[:500]}
        )
        return rejected

    async def rollback(self, containment_id: str, *, actor: str, note: str) -> ContainmentAction:
        action = await self._store.get_containment(containment_id)
        if action.status is not ContainmentStatus.EXECUTED:
            raise InvalidStateError(f"containment {containment_id} is {action.status.value}")
        if self._lifecycle is None:
            raise DependencyUnavailableError("identity fabric is not configured")
        try:
            await self._lifecycle.reinstate(
                action.agent_id, reason=f"rollback of containment {containment_id}: {note}"
            )
        except ThreatDetectionError as exc:
            await self._record(
                actor, "containment.rollback", action.agent_id, "failure", {"error": exc.message}
            )
            raise
        now = self._clock.now()
        rolled = action.evolve(
            now=now, status=ContainmentStatus.ROLLED_BACK, rolled_back_by=actor, rolled_back_at=now
        )
        await self._store.update_containment(rolled, previous_version=action.version)
        await self._record(
            actor, "containment.rollback", action.agent_id, "success", {"note": note[:500]}
        )
        return rolled

    # ------------------------------------------------------------------ internals

    async def _execute(self, action: ContainmentAction, *, actor: str) -> ContainmentAction:
        now = self._clock.now()
        try:
            if self._lifecycle is None:
                raise DependencyUnavailableError("identity fabric is not configured")
            await self._lifecycle.suspend(action.agent_id, reason=action.reason)
        except ThreatDetectionError as exc:
            failed = action.evolve(
                now=now,
                status=ContainmentStatus.FAILED,
                error=exc.message[:500],
                attempts=action.attempts + 1,
            )
            await self._store.update_containment(failed, previous_version=action.version)
            await self._record(
                actor, "containment.execute", action.agent_id, "failure", {"error": exc.message}
            )
            log.warning("containment_failed", agent=action.agent_id, error=exc.message)
            return failed
        executed = action.evolve(
            now=now,
            status=ContainmentStatus.EXECUTED,
            executed_at=now,
            error=None,
            attempts=action.attempts + 1,
        )
        await self._store.update_containment(executed, previous_version=action.version)
        await self._record(
            actor,
            "containment.execute",
            action.agent_id,
            "success",
            {"containment_id": action.containment_id, "automatic": action.automatic},
        )
        return executed

    async def _link(self, alert: Alert, action: ContainmentAction) -> None:
        current = await self._store.get_alert(alert.alert_id)
        status = (
            AlertStatus.CONTAINED
            if action.status is ContainmentStatus.EXECUTED and current.status.open
            else current.status
        )
        if current.containment_id == action.containment_id and status is current.status:
            return
        linked = current.model_copy(
            update={
                "containment_id": action.containment_id,
                "status": status,
                "updated_at": self._clock.now(),
                "version": current.version + 1,
            }
        )
        await self._store.save_alert(
            AlertWrite(linked, current.version),
            now=self._clock.now(),
            outbox=[encode(linked, Activity.UPDATE)],
        )

    async def _sync_alert(self, action: ContainmentAction) -> None:
        await self._link(await self._store.get_alert(action.alert_id), action)

    async def _record(
        self, actor: str, action: str, resource: str, outcome: str, details: dict[str, object]
    ) -> None:
        await self._audit.record(
            actor=actor,
            action=action,
            resource=resource,
            outcome=outcome,
            correlation_id=correlation_id(),
            details=details,
        )
