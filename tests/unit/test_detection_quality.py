"""Measured detection and false-positive rates on synthetic, labelled agent traces.

Benign traces come from persona-driven Markov agents (with genuinely rare
transitions, off-hours sessions, occasional benign denials and concurrent
sessions); attack episodes of eight scenarios are injected after the
baseline period and labelled. The thresholds below are regression gates:
they sit just under the values measured on these seeds and documented in
docs/architecture/detection-evaluation.md.
"""

from __future__ import annotations

import pytest

from agent_threat_detection.detection.config import DetectionConfig
from agent_threat_detection.detection.detectors import BehaviouralDetectors
from agent_threat_detection.detection.pipeline import DetectionPipeline
from agent_threat_detection.detection.sigma import RuleSet
from agent_threat_detection.evaluation.metrics import EvaluationReport, evaluate
from agent_threat_detection.evaluation.simulator import (
    INTERNAL_SUFFIX,
    Scenario,
    TraceConfig,
    TraceGenerator,
)
from tests.conftest import ROOT


def run(seed: int, *, agents: int = 16, days: int = 12, episodes: int = 8) -> EvaluationReport:
    trace = TraceGenerator(
        TraceConfig(agents=agents, days=days, episodes_per_scenario=episodes, seed=seed)
    ).generate()
    pipeline = DetectionPipeline(
        BehaviouralDetectors(DetectionConfig(internal_domain_suffixes=(INTERNAL_SUFFIX,))),
        RuleSet.from_directory(ROOT / "rules"),
    )
    return evaluate(trace, pipeline)


@pytest.fixture(scope="module")
def report() -> EvaluationReport:
    return run(TraceConfig().seed)


def test_trace_is_large_and_labelled(report: EvaluationReport) -> None:
    assert report.benign_events > 30_000
    assert report.malicious_events > 500
    assert all(s.episodes == 8 for s in report.scenarios)


def test_overall_detection_rate(report: EvaluationReport) -> None:
    assert report.overall_detection_rate >= 0.95


@pytest.mark.parametrize("scenario", list(Scenario))
def test_every_scenario_is_detected(report: EvaluationReport, scenario: Scenario) -> None:
    result = report.scenario(scenario)
    assert result.detection_rate >= 0.85, result
    assert result.mean_events_to_detect is not None


def test_single_event_scenarios_are_detected_on_the_first_event(report: EvaluationReport) -> None:
    for scenario in (Scenario.CREDENTIAL_LEAK, Scenario.DEFENSE_EVASION):
        assert report.scenario(scenario).mean_events_to_detect == 1.0


def test_false_positive_rates(report: EvaluationReport) -> None:
    # Event level: under 0.1% of benign events raise an alert-level signal.
    assert report.benign_alert_rate <= 0.001
    # Agent-day level: under 10% of mature agent-days see any benign alert.
    assert report.benign_agent_day_alert_rate <= 0.10


def test_rates_hold_on_an_unseen_seed() -> None:
    other = run(3, agents=12, days=10, episodes=6)
    assert other.overall_detection_rate >= 0.95
    assert other.benign_alert_rate <= 0.001
    assert other.benign_agent_day_alert_rate <= 0.10


def test_determinism() -> None:
    a = TraceGenerator(TraceConfig(agents=2, days=6, episodes_per_scenario=1, seed=5)).generate()
    b = TraceGenerator(TraceConfig(agents=2, days=6, episodes_per_scenario=1, seed=5)).generate()
    assert [x.event for x in a] == [x.event for x in b]
