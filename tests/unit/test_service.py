"""Use cases: ingest, deduplication, analyst workflow and containment."""

from __future__ import annotations

import asyncio
from datetime import timedelta
from pathlib import Path

import pytest
from agentic_core.audit import AuditEvent, verify_chain

from agent_threat_detection.application.service import Resolution
from agent_threat_detection.domain.errors import (
    ConflictError,
    DependencyUnavailableError,
    InvalidStateError,
    NotFoundError,
)
from agent_threat_detection.domain.events import EventKind
from agent_threat_detection.domain.findings import AlertStatus, ContainmentStatus, Severity
from agent_threat_detection.infrastructure.database import AlertQuery
from agent_threat_detection.runtime.container import Container
from tests.conftest import (
    START,
    FakeLifecycle,
    agent_uri,
    baseline_events,
    event,
)

END = START + timedelta(seconds=400 * 45)


def tamper(agent: str | None = None, at_offset: int = 0) -> list:  # type: ignore[type-arg]
    return [
        event(
            at=END + timedelta(seconds=at_offset),
            agent=agent,
            action="cloudtrail:StopLogging",
            tool="aws.cloudtrail",
            session_id="s-attack",
        )
    ]


async def tamper_alert(container: Container, alert_ids: list[str]) -> str:
    for alert_id in alert_ids:
        if (await container.service.get_alert(alert_id)).rule_id == "atd-audit-tampering":
            return alert_id
    raise AssertionError("no audit-tampering alert")


async def test_ingest_builds_baseline_then_alerts_and_auto_contains(
    container: Container, lifecycle: FakeLifecycle
) -> None:
    service = container.service
    clean = await service.ingest(baseline_events(), source="native", actor="collector")
    assert clean.accepted == 400
    assert not clean.alerts_opened
    replay = await service.ingest(baseline_events(5), source="native", actor="collector")
    assert replay.accepted == 5  # new event ids
    duplicate_batch = baseline_events(3)
    first = await service.ingest(duplicate_batch, source="native", actor="collector")
    again = await service.ingest(duplicate_batch, source="native", actor="collector")
    assert first.accepted == 3
    assert again.duplicates == 3
    assert again.accepted == 0

    result = await service.ingest(tamper(), source="native", actor="collector")
    assert result.alerts_opened
    assert result.containment
    alert = await service.get_alert(await tamper_alert(container, result.alerts_opened))
    assert alert.severity is Severity.CRITICAL
    assert alert.status is AlertStatus.CONTAINED
    assert lifecycle.calls[0][:2] == ("suspend", agent_uri())

    # The same activity again within the dedup window updates the same alert.
    repeat = await service.ingest(tamper(at_offset=60), source="native", actor="collector")
    assert alert.alert_id in repeat.alerts_updated
    assert not repeat.alerts_opened
    assert (await service.get_alert(alert.alert_id)).count == 2
    assert len(lifecycle.calls) == 1  # still one active containment

    risk = await service.agent_risk(agent_uri())
    assert risk.baseline_mature
    assert risk.open_alerts >= 1
    assert risk.containment is not None
    assert risk.containment.status is ContainmentStatus.EXECUTED
    with pytest.raises(NotFoundError):
        await service.agent_risk(agent_uri("never-seen"))


async def test_false_positive_learns_suppresses_and_rolls_back(
    container: Container, lifecycle: FakeLifecycle
) -> None:
    service = container.service
    await service.ingest(baseline_events(), source="native", actor="c")
    result = await service.ingest(tamper(), source="native", actor="c")
    alert_id = await tamper_alert(container, result.alerts_opened)
    resolved = await service.resolve(
        alert_id, resolution=Resolution.FALSE_POSITIVE, analyst="alice", note="approved change"
    )
    assert resolved.status is AlertStatus.FALSE_POSITIVE
    assert [c[0] for c in lifecycle.calls] == ["suspend", "reinstate"]
    profile = await container.store.get_profile(agent_uri())
    assert profile is not None
    assert resolved.dedup_key in profile.suppressed
    with pytest.raises(InvalidStateError):
        await service.resolve(alert_id, resolution=Resolution.TRUE_POSITIVE, analyst="a", note="x")
    # Suppressed key: the same activity no longer opens an alert.
    later = await service.ingest(tamper(at_offset=7200), source="native", actor="c")
    assert alert_id not in later.alerts_opened
    for opened in later.alerts_opened:
        assert (await service.get_alert(opened)).dedup_key != resolved.dedup_key


async def test_acknowledge_and_true_positive(container: Container) -> None:
    service = container.service
    result = await service.ingest(
        [event(EventKind.TOOL_CALL, action="iam:AttachRolePolicy", outcome="success")],
        source="native",
        actor="c",
    )
    alert_id = result.alerts_opened[0]
    acknowledged = await service.acknowledge(alert_id, analyst="bob", note="triaging")
    assert acknowledged.status is AlertStatus.ACKNOWLEDGED
    with pytest.raises(InvalidStateError):
        await service.acknowledge(alert_id, analyst="bob", note="again")
    done = await service.resolve(
        alert_id, resolution=Resolution.TRUE_POSITIVE, analyst="bob", note="ok"
    )
    assert done.status is AlertStatus.RESOLVED
    listed = await service.list_alerts(AlertQuery(status=AlertStatus.RESOLVED))
    assert [a.alert_id for a in listed] == [alert_id]
    assert await service.list_alerts(AlertQuery(min_severity=Severity.CRITICAL)) == []


async def test_high_alert_waits_for_approval_then_executes(
    container: Container, lifecycle: FakeLifecycle
) -> None:
    service = container.service
    result = await service.ingest(
        [event(action="shell.exec", session_id="s1")], source="native", actor="c"
    )
    action = await container.store.get_containment(result.containment[0])
    assert action.status is ContainmentStatus.PENDING_APPROVAL
    assert action.matched_rules == ("approve-high",)
    assert not lifecycle.calls
    containment = service.containment
    with pytest.raises(InvalidStateError, match="cannot approve their own"):
        await containment.approve(action.containment_id, approver=action.requested_by, note="self")
    executed = await containment.approve(action.containment_id, approver="carol", note="confirmed")
    assert executed.status is ContainmentStatus.EXECUTED
    assert executed.approved_by == "carol"
    alert = await service.get_alert(action.alert_id)
    assert alert.status is AlertStatus.CONTAINED
    with pytest.raises(InvalidStateError):
        await containment.approve(action.containment_id, approver="carol", note="again")
    with pytest.raises(InvalidStateError):
        await containment.reject(action.containment_id, approver="carol", note="late")
    rolled = await containment.rollback(action.containment_id, actor="carol", note="contained")
    assert rolled.status is ContainmentStatus.ROLLED_BACK
    with pytest.raises(InvalidStateError):
        await containment.rollback(action.containment_id, actor="carol", note="twice")


async def test_reject_and_failure_then_retry(
    container: Container, lifecycle: FakeLifecycle
) -> None:
    service = container.service
    containment = service.containment
    pending = await service.ingest([event(action="shell.exec")], source="native", actor="c")
    action_id = pending.containment[0]
    rejected = await containment.reject(action_id, approver="dave", note="sandboxed tool")
    assert rejected.status is ContainmentStatus.REJECTED

    lifecycle.fail = True
    other = await service.ingest(
        [event(agent=agent_uri("other"), action="shell.exec")], source="native", actor="c"
    )
    failed = await containment.approve(other.containment[0], approver="dave", note="go")
    assert failed.status is ContainmentStatus.FAILED
    assert failed.error
    lifecycle.fail = False
    retried = await containment.approve(other.containment[0], approver="dave", note="retry")
    assert retried.status is ContainmentStatus.EXECUTED
    assert retried.attempts == 2
    lifecycle.fail = True
    with pytest.raises(DependencyUnavailableError):
        await containment.rollback(retried.containment_id, actor="dave", note="x")


async def test_policy_decisions_for_containment(container: Container) -> None:
    service = container.service
    containment = service.containment
    protected = agent_uri("identity-fabric", "platform")
    result = await service.ingest(
        [event(agent=protected, action="cloudtrail:StopLogging")], source="native", actor="c"
    )
    action = await container.store.get_containment(result.containment[0])
    assert action.status is ContainmentStatus.PENDING_APPROVAL
    assert "approve-protected-agents" in action.matched_rules

    medium = await service.ingest(
        [event(agent=agent_uri("m"), action="token.exchange", kind=EventKind.TOKEN)] * 0
        + [
            event(
                EventKind.DATA_TRANSFER,
                agent=agent_uri("m"),
                action="http.post",
                destination="x.webhook.site",
            )
        ],
        source="native",
        actor="c",
    )
    alert = await service.get_alert(medium.alerts_opened[0])
    decision = containment.evaluate(
        alert.model_copy(update={"severity": Severity.MEDIUM}),
        requester_kind="service",
        requester="svc",
    )
    assert decision.decision.value == "deny"
    assert (
        await service.request_containment(
            alert.alert_id, requester=agent_uri("soc"), requester_kind="agent", reason="looks bad"
        )
        is not None
    )  # HIGH rule -> agent request needs approval
    low_alert = alert.model_copy(update={"severity": Severity.MEDIUM, "alert_id": "x"})
    assert (
        containment.evaluate(low_alert, requester_kind="agent", requester="a").decision.value
        == "deny"
    )


async def test_request_containment_rejects_closed_alerts(container: Container) -> None:
    service = container.service
    result = await service.ingest([event(action="shell.exec")], source="native", actor="c")
    alert_id = result.alerts_opened[0]
    await service.resolve(alert_id, resolution=Resolution.TRUE_POSITIVE, analyst="a", note="done")
    with pytest.raises(InvalidStateError):
        await service.request_containment(
            alert_id, requester="a", requester_kind="agent", reason="x"
        )


async def test_conflicting_writers_are_retried(
    container: Container, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = container.store
    original = store.commit_batch
    calls = {"n": 0}

    async def flaky(**kwargs: object) -> None:
        calls["n"] += 1
        if calls["n"] == 1:
            raise ConflictError("another replica won")
        await original(**kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(store, "commit_batch", flaky)
    result = await container.service.ingest(baseline_events(10), source="native", actor="c")
    assert result.accepted == 10
    assert calls["n"] == 2

    async def always(**_: object) -> None:
        raise ConflictError("hot agent")

    monkeypatch.setattr(store, "commit_batch", always)
    with pytest.raises(ConflictError):
        await container.service.ingest(baseline_events(2), source="native", actor="c")


async def test_audit_chain_is_signed_and_complete(container: Container) -> None:
    await container.service.ingest(tamper(), source="native", actor="collector")
    path = Path(container.settings.audit_log_path)
    text = await asyncio.to_thread(path.read_text, encoding="utf-8")
    events = [AuditEvent.model_validate_json(line) for line in text.splitlines()]
    actions = {e.action for e in events}
    assert {
        "telemetry.ingest",
        "alert.open",
        "containment.decide",
        "containment.execute",
    } <= actions
    public = container.audit._signer.public_key()  # type: ignore[attr-defined]
    assert verify_chain(events, {"audit-ephemeral": public}) == len(events)
