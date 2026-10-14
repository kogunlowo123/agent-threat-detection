"""Alert model, OCSF mapping, SIEM sinks and the outbox dispatcher."""

from __future__ import annotations

import asyncio
import json
from datetime import timedelta
from pathlib import Path

import httpx
import pytest

from agent_threat_detection.detection.techniques import from_tag, known, technique
from agent_threat_detection.domain.findings import (
    MAX_EVIDENCE,
    Alert,
    AlertStatus,
    AlertSummary,
    ContainmentAction,
    ContainmentStatus,
    Severity,
    Signal,
)
from agent_threat_detection.infrastructure.database import AlertWrite, ThreatStore
from agent_threat_detection.infrastructure.siem import (
    Activity,
    FileSiemSink,
    HttpSiemSink,
    SiemDispatcher,
    encode,
    to_ocsf,
)
from agent_threat_detection.runtime.container import Container
from tests.conftest import START, FakeClock, FakeSink, agent_uri


def signal(detector: str = "sigma", severity: Severity = Severity.HIGH, **kw: object) -> Signal:
    data: dict[str, object] = {
        "detector": detector,
        "rule_id": "atd-audit-tampering",
        "title": "Agent disables audit logging",
        "description": "cloudtrail:StopLogging",
        "severity": severity,
        "score": 0.8,
        "discriminator": "x",
        "techniques": (technique("T1562"),),
        "evidence": {"action": "cloudtrail:StopLogging"},
        "event_id": "e1",
        "agent_id": agent_uri(),
        "observed_at": START,
    }
    data.update(kw)
    return Signal.model_validate(data)


def test_alert_lifecycle_and_dedup_key() -> None:
    first = signal()
    assert first.dedup_key() == signal(event_id="other").dedup_key()
    assert first.dedup_key() != signal(discriminator="y").dedup_key()
    alert = Alert.open_from(first, now=START)
    merged = alert
    for i in range(MAX_EVIDENCE + 5):
        merged = merged.merge(
            signal(
                severity=Severity.CRITICAL,
                score=0.95,
                event_id=f"e{i}",
                observed_at=START + timedelta(seconds=i),
            ),
            now=START,
        )
    assert merged.count == MAX_EVIDENCE + 6
    assert merged.severity is Severity.CRITICAL
    assert merged.score == 0.95
    assert len(merged.evidence) == MAX_EVIDENCE
    assert merged.version == alert.version + MAX_EVIDENCE + 5
    acknowledged = merged.with_status(AlertStatus.ACKNOWLEDGED, now=START, by="bob", note="looking")
    assert acknowledged.resolved_by == "bob"
    assert acknowledged.status.open
    assert not AlertStatus.FALSE_POSITIVE.open
    summary = AlertSummary.of(merged)
    assert summary.techniques == ["T1562"]
    assert summary.severity == "critical"
    assert Severity.parse(" High ") is Severity.HIGH
    assert Severity.HIGH.label == "high"


def test_containment_action_evolves_with_versions() -> None:
    action = ContainmentAction(
        agent_id=agent_uri(),
        alert_id="a1",
        status=ContainmentStatus.PENDING_APPROVAL,
        automatic=False,
        decision="require_approval",
        matched_rules=("approve-high",),
        policy_version="v",
        policy_digest="d",
        reason="r",
        requested_by="svc",
        created_at=START,
        updated_at=START,
    )
    done = action.evolve(now=START + timedelta(seconds=1), status=ContainmentStatus.EXECUTED)
    assert done.version == 2
    assert done.updated_at > action.updated_at
    assert ContainmentStatus.FAILED.active
    assert not ContainmentStatus.ROLLED_BACK.active


def test_techniques() -> None:
    assert from_tag("attack.t1562.008") == technique("T1562")
    assert from_tag("attack.execution") is None
    assert from_tag("atlas.aml.t0051") == technique("AML.T0051")
    assert from_tag("cve.2021") is None
    assert known("T1059")
    assert not known("T0000")


def test_ocsf_detection_finding_shape() -> None:
    alert = Alert.open_from(signal(), now=START)
    contained = alert.model_copy(update={"containment_id": "c1"})
    finding = to_ocsf(contained, Activity.CREATE)
    assert finding["class_uid"] == 2004
    assert finding["category_uid"] == 2
    assert finding["type_uid"] == 200401
    assert finding["severity_id"] == 4
    assert finding["status"] == "New"
    assert finding["metadata"]["version"] == "1.3.0"
    assert finding["finding_info"]["analytic"]["type"] == "Rule"
    assert finding["finding_info"]["attacks"][0]["technique"]["uid"] == "T1562"
    assert finding["finding_info"]["attacks"][0]["tactic"]["name"] == "Defense Evasion"
    assert finding["resources"][0]["uid"] == agent_uri()
    assert finding["unmapped"] == {"containment_id": "c1"}
    behavioural = to_ocsf(
        Alert.open_from(signal("exfiltration.volume"), now=START).with_status(
            AlertStatus.FALSE_POSITIVE, now=START
        ),
        Activity.CLOSE,
    )
    assert behavioural["finding_info"]["analytic"]["type"] == "Behavioral"
    assert behavioural["status_id"] == 3
    assert behavioural["activity_name"] == "Close"
    assert json.loads(encode(alert, Activity.UPDATE))["activity_id"] == 2


async def test_http_sink_formats(tmp_path: Path) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200)

    token = tmp_path / "token"
    token.write_text("siem-token\n", encoding="utf-8")
    finding = to_ocsf(Alert.open_from(signal(), now=START), Activity.CREATE)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        await HttpSiemSink(
            "https://siem.corp.test/ocsf", token_file=token, fmt="ocsf", client=http
        ).send([finding])
        await HttpSiemSink(
            "https://siem.corp.test/services/collector",
            token_file=token,
            fmt="splunk_hec",
            client=http,
        ).send([finding, finding])
        await HttpSiemSink(
            "https://siem.corp.test/open", token_file=None, fmt="ocsf", client=http
        ).send([finding])
    assert seen[0].headers["authorization"] == "Bearer siem-token"
    assert json.loads(seen[0].content)[0]["class_uid"] == 2004
    assert seen[1].headers["authorization"] == "Splunk siem-token"
    lines = seen[1].content.decode().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["sourcetype"] == "ocsf:detection_finding"
    assert "authorization" not in seen[2].headers
    with pytest.raises(ValueError, match="unsupported"):
        HttpSiemSink("https://x", token_file=None, fmt="cef", client=httpx.AsyncClient())


async def test_http_sink_raises_on_error_status() -> None:
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(503))
    ) as http:
        with pytest.raises(httpx.HTTPStatusError):
            await HttpSiemSink(
                "https://siem.corp.test", token_file=None, fmt="ocsf", client=http
            ).send([{}])


async def test_file_sink(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "ocsf.jsonl"
    sink = FileSiemSink(path)
    await sink.send([{"a": 1}, {"b": 2}])
    assert [json.loads(line) for line in path.read_text().splitlines()] == [{"a": 1}, {"b": 2}]


async def test_dispatcher_delivers_and_backs_off(container: Container, clock: FakeClock) -> None:
    store: ThreatStore = container.store
    alert = Alert.open_from(signal(), now=clock.now())
    await store.save_alert(
        AlertWrite(alert, None), now=clock.now(), outbox=[encode(alert, Activity.CREATE)] * 3
    )
    sink = FakeSink(fail=True)
    results: list[tuple[int, int]] = []
    dispatcher = SiemDispatcher(
        store, sink, now=clock.now, batch_size=2, on_result=lambda d, f: results.append((d, f))
    )
    assert await dispatcher.dispatch_once() == 0
    assert results == [(0, 2)]
    assert await store.outbox_backlog() == 3
    sink.fail = False
    # The failed two wait out their back-off; the third is due now.
    assert await dispatcher.dispatch_once() == 1
    clock.advance(10)
    assert await dispatcher.dispatch_once() == 2
    assert await dispatcher.dispatch_once() == 0
    assert len(sink.findings) == 3
    assert await store.outbox_backlog() == 0
    clock.advance(8 * 86400)
    assert await store.purge_delivered(clock.now()) == 3


async def test_dispatcher_loop_survives_errors(container: Container) -> None:
    calls = {"n": 0}

    class Exploding(SiemDispatcher):
        async def dispatch_once(self) -> int:
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("db hiccup")
            return 100

    sleeps: list[float] = []

    async def sleep(seconds: float) -> None:
        sleeps.append(seconds)
        if len(sleeps) == 2:
            raise asyncio.CancelledError

    dispatcher = Exploding(container.store, FakeSink(), now=container.clock.now, batch_size=100)
    with pytest.raises(asyncio.CancelledError):
        await dispatcher.run_forever(5.0, sleep=sleep)
    assert sleeps == [5.0, 0]
