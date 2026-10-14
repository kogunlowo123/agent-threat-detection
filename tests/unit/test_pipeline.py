"""Learning quarantine, risk accumulation, correlation and analyst feedback."""

from __future__ import annotations

from datetime import timedelta

from agent_threat_detection.detection.config import DetectionConfig
from agent_threat_detection.detection.detectors import BehaviouralDetectors
from agent_threat_detection.detection.pipeline import DetectionPipeline, suppression_expiry
from agent_threat_detection.detection.sigma import RuleSet
from agent_threat_detection.domain.events import EventKind
from agent_threat_detection.domain.findings import Severity
from tests.conftest import ROOT, START, TEST_DETECTION, agent_uri, baseline_events, event

END = START + timedelta(seconds=400 * 45)


def build(config: DetectionConfig = TEST_DETECTION) -> DetectionPipeline:
    return DetectionPipeline(BehaviouralDetectors(config), RuleSet.from_directory(ROOT / "rules"))


def trained(pipeline: DetectionPipeline):  # type: ignore[no-untyped-def]
    profile = pipeline.new_profile(agent_uri(), START)
    for e in baseline_events():
        pipeline.process(profile, e)
    return profile


def test_alert_level_events_are_never_learned() -> None:
    pipeline = build()
    profile = trained(pipeline)
    result = pipeline.process(
        profile,
        event(
            EventKind.DATA_TRANSFER,
            at=END,
            action="http.post",
            destination="x.attacker.test",
            bytes_out=4000,
        ),
    )
    assert result.alertable
    assert not result.learned
    assert "x.attacker.test" not in profile.destinations


def test_low_anomalies_are_learned_only_after_recurring_on_distinct_days() -> None:
    pipeline = build(TEST_DETECTION.model_copy(update={"quarantine_days": 2}))
    profile = trained(pipeline)
    profile.hours[10] += 5000
    night = END.replace(hour=3)
    first = pipeline.process(profile, event(at=night + timedelta(days=1), session_id="q1"))
    assert {s.detector for s in first.signals} == {"time.off_hours"}
    assert not first.learned
    second = pipeline.process(profile, event(at=night + timedelta(days=2), session_id="q2"))
    assert second.learned


def test_risk_threshold_from_correlated_low_signals() -> None:
    pipeline = build()
    profile = trained(pipeline)
    profile.hours[10] += 5000
    fired = []
    for i in range(12):
        result = pipeline.process(
            profile,
            event(
                EventKind.AUTHORIZATION,
                at=END.replace(hour=3) + timedelta(days=1, minutes=i),
                action=f"crm:read_{i}",
                outcome="denied",
            ),
        )
        fired.extend(s for s in result.alertable if s.detector == "risk.threshold")
        # Isolate risk accumulation from the denial-burst detector.
        profile.windows.pop("denials", None)
    assert fired
    assert fired[0].severity is Severity.HIGH
    assert 0.8 <= fired[0].score <= 1.0


def test_suppressed_keys_are_not_alertable_and_feedback_updates_the_baseline() -> None:
    pipeline = build()
    profile = trained(pipeline)
    transfer = event(
        EventKind.DATA_TRANSFER,
        at=END,
        action="http.post",
        destination="new-partner.corp.internal",
        bytes_out=4000,
        delegate=agent_uri("helper", "workers"),
    )
    first = pipeline.process(profile, transfer)
    alert_signal = next(s for s in first.signals if s.detector == "exfiltration.new_destination")
    pipeline.accept_as_benign(
        profile,
        alert_signal.dedup_key(),
        [
            alert_signal.evidence,
            {
                "delegate": agent_uri("helper", "workers"),
                "tool": "new.tool",
                "classification": "CONFIDENTIAL",
                "new_scopes": ["crm:write", 3],
            },
        ],
        until=suppression_expiry(END, pipeline.config),
    )
    assert "new-partner.corp.internal" in profile.destinations
    assert agent_uri("helper", "workers") in profile.delegates
    assert "new.tool" in profile.tools
    assert "crm:write" in profile.scopes
    assert profile.max_classification == 2
    assert profile.is_suppressed(alert_signal.dedup_key(), END + timedelta(days=1))
    # Suppressions expire with the event clock.
    pipeline.process(profile, event(at=END + timedelta(days=31)))
    assert not profile.suppressed


def test_sigma_aggregation_runs_inside_the_pipeline() -> None:
    pipeline = build()
    profile = pipeline.new_profile(agent_uri(), START)
    fired = set()
    for i in range(42):
        result = pipeline.process(
            profile,
            event(at=START + timedelta(seconds=i), action="patient.read", classification=3),
        )
        fired |= {s.rule_id for s in result.alertable}
    assert "atd-restricted-bulk-read" in fired
