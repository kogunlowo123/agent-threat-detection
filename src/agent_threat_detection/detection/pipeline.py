"""Telemetry -> behavioural baseline -> detection -> scoring, for one event at a time.

The pipeline is pure with respect to I/O: it mutates the ``AgentProfile`` it is
given and returns the signals that should become alerts. Persistence, alert
deduplication and containment live in the application layer.
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from agentic_core.domain.classification import DataClassification

from agent_threat_detection.detection.baseline import AgentProfile, session_slot
from agent_threat_detection.detection.config import DetectionConfig
from agent_threat_detection.detection.detectors import SEQUENCE_KINDS, BehaviouralDetectors
from agent_threat_detection.detection.sigma import RuleSet
from agent_threat_detection.detection.techniques import technique
from agent_threat_detection.domain.events import AgentEvent, EventKind, Outcome
from agent_threat_detection.domain.findings import Severity, Signal

SEVERITY_WEIGHT = {
    Severity.INFORMATIONAL: 0.1,
    Severity.LOW: 0.5,
    Severity.MEDIUM: 0.8,
    Severity.HIGH: 1.0,
    Severity.CRITICAL: 1.0,
}
# Single rare transitions are common in benign traces; they are evidence for the
# windowed sequence detector and for the learning quarantine, not for risk.
RISK_EXEMPT = frozenset({"sequence.rare_transition"})
# Detectors whose firing inside a taint window indicates an injection-driven shift.
SHIFT_SOURCES = ("sequence.", "exfiltration.", "privilege.", "delegation.", "sigma")


@dataclass
class ProcessResult:
    signals: list[Signal] = field(default_factory=list)
    alertable: list[Signal] = field(default_factory=list)
    learned: bool = False


class DetectionPipeline:
    def __init__(self, detectors: BehaviouralDetectors, rules: RuleSet) -> None:
        self._detectors = detectors
        self._rules = rules
        self._config = detectors.config

    @property
    def config(self) -> DetectionConfig:
        return self._config

    @property
    def rules(self) -> RuleSet:
        return self._rules

    def new_profile(self, agent_id: str, at: datetime) -> AgentProfile:
        return AgentProfile.new(agent_id, at=at, order=self._config.markov_order)

    def process(self, profile: AgentProfile, event: AgentEvent) -> ProcessResult:
        signals = self._detectors.evaluate(profile, event)
        signals.extend(self._rules.evaluate(event, profile))
        shift = self._behaviour_shift(profile, event, signals)
        if shift is not None:
            signals.append(shift)
        risk_signal = self._score(profile, event, signals)
        if risk_signal is not None:
            signals.append(risk_signal)

        learn = self._learnable(profile, event, signals)
        if event.kind in SEQUENCE_KINDS:
            self._track_surprise(profile, event, learn=learn)
        self._bookkeeping(profile, event, signals)
        if learn:
            self._learn(profile, event)
        elif event.kind in SEQUENCE_KINDS:
            profile.sequence.advance(event.subject, session=event.session)

        alertable = [
            s
            for s in signals
            if s.severity >= self._config.alert_min_severity
            and not profile.is_suppressed(s.dedup_key(), event.timestamp)
        ]
        return ProcessResult(signals=signals, alertable=alertable, learned=learn)

    def _learnable(self, profile: AgentProfile, event: AgentEvent, signals: list[Signal]) -> bool:
        """Clean events are learned; LOW anomalies only after multi-day recurrence; never worse.

        This keeps an attacker from teaching the baseline within one campaign:
        a new pattern must persist across ``quarantine_days`` distinct days
        without ever raising a MEDIUM or higher signal before it is normal.
        """
        anomalies = [s for s in signals if s.severity > Severity.INFORMATIONAL]
        if not anomalies:
            return True
        if any(s.severity > Severity.LOW for s in anomalies):
            return False
        keys = sorted({s.dedup_key() for s in anomalies})
        days = profile.quarantine_days(keys, event.timestamp)
        return days >= self._config.quarantine_days

    # --------------------------------------------------------------- correlation

    def _behaviour_shift(
        self, profile: AgentProfile, event: AgentEvent, signals: list[Signal]
    ) -> Signal | None:
        tainted = (
            profile.taint_events_left > 0
            and profile.taint_until is not None
            and event.timestamp <= profile.taint_until
        )
        if not tainted:
            return None
        triggers = [
            s
            for s in signals
            if s.detector.startswith(SHIFT_SOURCES) and s.severity >= Severity.LOW
        ]
        if not triggers:
            return None
        strongest = max(triggers, key=lambda s: (s.severity, s.score))
        severity = Severity.CRITICAL if strongest.severity >= Severity.HIGH else Severity.HIGH
        return Signal(
            detector="injection.behavior_shift",
            rule_id="injection.behavior_shift",
            title="Behaviour shift after ingesting injected content",
            description=f"{strongest.title} occurred shortly after the agent ingested content "
            "with prompt-injection markers; the agent is likely following injected instructions.",
            severity=severity,
            score=max(0.9, strongest.score),
            discriminator=profile.taint_event_id or "",
            techniques=(technique("AML.T0051"), *strongest.techniques),
            evidence={
                "injected_event_id": profile.taint_event_id,
                "triggered_by": [s.detector for s in triggers],
                "trigger_evidence": strongest.evidence,
            },
            event_id=event.event_id,
            agent_id=event.agent_id,
            observed_at=event.timestamp,
        )

    # ------------------------------------------------------------------- scoring

    def _score(
        self, profile: AgentProfile, event: AgentEvent, signals: list[Signal]
    ) -> Signal | None:
        cfg = self._config
        before = profile.decayed_risk(event.timestamp, half_life_s=cfg.risk_half_life_s)
        remaining = 1.0 - before
        for signal in signals:
            if signal.detector not in RISK_EXEMPT:
                remaining *= 1.0 - signal.score * SEVERITY_WEIGHT[signal.severity]
        after = 1.0 - remaining
        profile.risk = round(after, 6)
        profile.risk_at = event.timestamp
        if after < cfg.risk_alert_threshold or before >= cfg.risk_alert_threshold:
            return None
        if any(s.severity >= cfg.alert_min_severity for s in signals):
            return None  # this event already raises its own alert; the risk alert adds nothing
        contributors = sorted({s.detector for s in signals})
        return Signal(
            detector="risk.threshold",
            rule_id="risk.threshold",
            title="Agent risk score crossed the alert threshold",
            description=f"Accumulated risk {after:.2f} >= {cfg.risk_alert_threshold:.2f} from "
            "correlated low-confidence anomalies.",
            severity=Severity.HIGH,
            score=round(after, 4),
            discriminator="",
            techniques=tuple({t.uid: t for s in signals for t in s.techniques}.values()),
            evidence={"risk": round(after, 4), "previous": round(before, 4), "now": contributors},
            event_id=event.event_id,
            agent_id=event.agent_id,
            observed_at=event.timestamp,
        )

    # ------------------------------------------------------------------ learning

    def _track_surprise(self, profile: AgentProfile, event: AgentEvent, *, learn: bool) -> None:
        """Record this step's surprise (under the model before it learns the step)."""
        cfg = self._config
        surprise = profile.sequence.transition(
            event.subject,
            session=event.session,
            alpha=cfg.smoothing_alpha,
            min_support=cfg.min_context_support,
        ).surprise
        recent = session_slot(profile.recent_surprise, event.session)
        recent.append(round(surprise, 4))
        del recent[: -cfg.sequence_window]
        if learn:
            profile.surprise.update(surprise)

    def _bookkeeping(self, profile: AgentProfile, event: AgentEvent, signals: list[Signal]) -> None:
        """State updated for every event, anomalous or not."""
        cfg = self._config
        profile.events_seen += 1
        if profile.last_event_at is None or event.timestamp > profile.last_event_at:
            profile.last_event_at = event.timestamp
        minute = int(event.timestamp.timestamp() // 60)
        if profile.minute != minute:
            if profile.minute is not None and profile.minute_count > 0:
                profile.rate.update(float(profile.minute_count))
            profile.minute, profile.minute_count = minute, 0
        profile.minute_count += 1
        if event.kind is EventKind.AUTHORIZATION and event.outcome is Outcome.DENIED:
            profile.window_add(
                "denials", event.timestamp, event.action, span_s=cfg.denial_burst_window_s
            )
        if event.kind is EventKind.DELEGATION and event.delegate:
            profile.window_add(
                "delegates", event.timestamp, event.delegate, span_s=cfg.delegation_fanout_window_s
            )
        self._egress_bookkeeping(profile, event, signals)
        if any(s.detector == "injection.content" for s in signals):
            profile.taint_until = event.timestamp + timedelta(seconds=cfg.taint_window_s)
            profile.taint_events_left = cfg.taint_events
            profile.taint_event_id = event.event_id
        elif profile.taint_events_left > 0:
            profile.taint_events_left -= 1
        for key, expiry in list(profile.suppressed.items()):
            if expiry <= event.timestamp:
                del profile.suppressed[key]

    def _egress_bookkeeping(
        self, profile: AgentProfile, event: AgentEvent, signals: list[Signal]
    ) -> None:
        """Close the previous egress window (learning it if clean) and add this transfer."""
        if event.bytes_out <= 0 or not event.destination:
            return
        cfg = self._config
        window = int(event.timestamp.timestamp() // cfg.egress_window_s)
        if profile.egress_window != window:
            if profile.egress_window_bytes > 0 and not profile.egress_window_flagged:
                profile.egress_windows.update(math.log1p(profile.egress_window_bytes))
            profile.egress_window = window
            profile.egress_window_bytes = 0
            profile.egress_window_flagged = False
        profile.egress_window_bytes += event.bytes_out
        if any(s.severity >= Severity.MEDIUM for s in signals):
            # Windows containing alert-level activity are never learned.
            profile.egress_window_flagged = True

    @staticmethod
    def _learn(profile: AgentProfile, event: AgentEvent) -> None:
        profile.events_learned += 1
        profile.hours[event.timestamp.hour] += 1
        if event.kind in SEQUENCE_KINDS:
            subject = event.subject
            profile.tools[subject] = profile.tools.get(subject, 0) + 1
            profile.sequence.learn(subject, session=event.session)
        if event.destination:
            profile.destinations[event.destination] = (
                profile.destinations.get(event.destination, 0) + 1
            )
            if event.bytes_out > 0:
                profile.egress.update(math.log1p(event.bytes_out))
        if event.delegate:
            profile.delegates[event.delegate] = profile.delegates.get(event.delegate, 0) + 1
            depth = len(event.delegation_chain) + 1
            profile.max_delegation_depth = max(profile.max_delegation_depth, depth)
        if event.kind is EventKind.AUTHORIZATION and event.outcome is Outcome.SUCCESS:
            profile.scopes[event.action] = profile.scopes.get(event.action, 0) + 1
        for scope in event.scopes_requested:
            profile.scopes[scope] = profile.scopes.get(scope, 0) + 1
        profile.max_classification = max(profile.max_classification, int(event.classification))

    @staticmethod
    def accept_as_benign(
        profile: AgentProfile,
        dedup_key: str,
        evidence: Iterable[Mapping[str, Any]],
        *,
        until: datetime,
    ) -> None:
        """Analyst feedback: suppress this alert key and fold its evidence into the baseline."""
        profile.suppressed[dedup_key] = until
        for item in evidence:
            destination = item.get("destination")
            if isinstance(destination, str):
                profile.destinations.setdefault(destination, 1)
            delegate = item.get("delegate")
            if isinstance(delegate, str):
                profile.delegates.setdefault(delegate, 1)
            tool = item.get("tool")
            if isinstance(tool, str):
                profile.tools.setdefault(tool, 1)
            classification = item.get("classification")
            if isinstance(classification, str) and classification in DataClassification.__members__:
                profile.max_classification = max(
                    profile.max_classification, int(DataClassification[classification])
                )
            for scope in item.get("new_scopes", []) or []:
                if isinstance(scope, str):
                    profile.scopes.setdefault(scope, 1)


def suppression_expiry(now: datetime, config: DetectionConfig) -> datetime:
    return now + timedelta(days=config.suppression_days)
