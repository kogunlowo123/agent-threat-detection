"""Replay a labelled trace through the detection pipeline and measure it.

Definitions:

* An attack *episode* is detected when at least one alert-level signal
  (severity >= the configured alert threshold) fires on one of its events.
* Time to detect is the number of episode events up to and including the
  first detecting event.
* The benign alert rate is the share of benign events that produced an
  alert-level signal (the event-level false-positive rate).
* The benign agent-day alert rate is the share of (agent, day) pairs after
  baseline maturity on which any benign event produced an alert-level signal.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable

from pydantic import BaseModel, ConfigDict

from agent_threat_detection.detection.baseline import AgentProfile
from agent_threat_detection.detection.pipeline import DetectionPipeline
from agent_threat_detection.evaluation.simulator import LabelledEvent, Scenario


class ScenarioResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    scenario: Scenario
    episodes: int
    detected: int
    detection_rate: float
    mean_events_to_detect: float | None
    detectors: dict[str, int]


class EvaluationReport(BaseModel):
    model_config = ConfigDict(frozen=True)

    events: int
    benign_events: int
    malicious_events: int
    benign_alert_events: int
    benign_alert_rate: float
    benign_agent_days: int
    benign_agent_days_with_alert: int
    benign_agent_day_alert_rate: float
    overall_detection_rate: float
    scenarios: tuple[ScenarioResult, ...]
    false_positive_detectors: dict[str, int]

    def scenario(self, scenario: Scenario) -> ScenarioResult:
        return next(s for s in self.scenarios if s.scenario is scenario)


def evaluate(trace: Iterable[LabelledEvent], pipeline: DetectionPipeline) -> EvaluationReport:
    profiles: dict[str, AgentProfile] = {}
    episode_scenario: dict[str, Scenario] = {}
    episode_seen: dict[str, int] = defaultdict(int)
    episode_detected_at: dict[str, int] = {}
    scenario_detectors: dict[Scenario, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    fp_detectors: dict[str, int] = defaultdict(int)
    benign = malicious = benign_alerts = 0
    mature_days: set[tuple[str, str]] = set()
    alert_days: set[tuple[str, str]] = set()

    for item in trace:
        event = item.event
        profile = profiles.get(event.agent_id)
        if profile is None:
            profile = profiles[event.agent_id] = pipeline.new_profile(
                event.agent_id, event.timestamp
            )
        was_mature = profile.mature(pipeline.config)
        result = pipeline.process(profile, event)
        if item.scenario is None or item.episode is None:
            benign += 1
            day = (event.agent_id, event.timestamp.date().isoformat())
            if was_mature:
                mature_days.add(day)
            if result.alertable:
                benign_alerts += 1
                alert_days.add(day)
                for signal in result.alertable:
                    fp_detectors[signal.detector] += 1
            continue
        malicious += 1
        episode_scenario[item.episode] = item.scenario
        episode_seen[item.episode] += 1
        if result.alertable and item.episode not in episode_detected_at:
            episode_detected_at[item.episode] = episode_seen[item.episode]
            for signal in result.alertable:
                scenario_detectors[item.scenario][signal.detector] += 1

    results: list[ScenarioResult] = []
    for scenario in Scenario:
        episodes = [e for e, s in episode_scenario.items() if s is scenario]
        detected = [e for e in episodes if e in episode_detected_at]
        delays = [episode_detected_at[e] for e in detected]
        results.append(
            ScenarioResult(
                scenario=scenario,
                episodes=len(episodes),
                detected=len(detected),
                detection_rate=round(len(detected) / len(episodes), 4) if episodes else 0.0,
                mean_events_to_detect=round(sum(delays) / len(delays), 2) if delays else None,
                detectors=dict(scenario_detectors[scenario]),
            )
        )
    total_episodes = sum(r.episodes for r in results)
    benign_days = len(mature_days)
    flagged_days = len(alert_days & mature_days)
    return EvaluationReport(
        events=benign + malicious,
        benign_events=benign,
        malicious_events=malicious,
        benign_alert_events=benign_alerts,
        benign_alert_rate=round(benign_alerts / benign, 6) if benign else 0.0,
        benign_agent_days=benign_days,
        benign_agent_days_with_alert=flagged_days,
        benign_agent_day_alert_rate=round(flagged_days / benign_days, 4) if benign_days else 0.0,
        overall_detection_rate=(
            round(sum(r.detected for r in results) / total_episodes, 4) if total_episodes else 0.0
        ),
        scenarios=tuple(results),
        false_positive_detectors=dict(fp_detectors),
    )
