"""Behavioural detectors.

Each detector inspects one event against the agent's profile *before* the
event is learned, and returns zero or more signals. Statistical detectors only
run once the baseline is mature; detectors for unambiguous indicators
(credentials in egress, delegation cycles, denial bursts, injected content)
run from the first event.
"""

from __future__ import annotations

import math
import re
from collections.abc import Callable
from typing import Any

from agentic_core.domain.classification import DataClassification
from agentic_core.security import PromptInjectionDetector, SecretScanner

from agent_threat_detection.detection.baseline import AgentProfile, missing_mass
from agent_threat_detection.detection.config import DetectionConfig
from agent_threat_detection.detection.techniques import technique
from agent_threat_detection.domain.events import AgentEvent, EventKind, Outcome
from agent_threat_detection.domain.findings import Severity, Signal, Technique

# Delegation is modelled by its own detectors; it interleaves with the tool plan
# at arbitrary points and would only add noise to the sequence model.
SEQUENCE_KINDS = frozenset({EventKind.TOOL_CALL, EventKind.DATA_TRANSFER, EventKind.CONTENT_INGEST})
EGRESS_KINDS = frozenset({EventKind.DATA_TRANSFER, EventKind.TOOL_CALL})
_PRIVILEGED_SCOPE = re.compile(r"(^\*$|:\*$|admin|iam[:.]|:delete|root|sudo|owner)", re.I)
_BASE64_RUN = re.compile(r"[A-Za-z0-9+/]{200,}={0,2}")
_HEX_RUN = re.compile(r"\b[0-9a-fA-F]{256,}\b")
NOVELTY_SCORE = {Severity.LOW: 0.3, Severity.MEDIUM: 0.55, Severity.HIGH: 0.75}


class BehaviouralDetectors:
    def __init__(
        self,
        config: DetectionConfig,
        *,
        injection: PromptInjectionDetector | None = None,
        secrets: SecretScanner | None = None,
    ) -> None:
        self._config = config
        self._injection = injection or PromptInjectionDetector()
        self._secrets = secrets or SecretScanner()
        self._detectors: tuple[Callable[[AgentProfile, AgentEvent, bool], list[Signal]], ...] = (
            self._sequence,
            self._time_of_day,
            self._rate,
            self._privilege,
            self._delegation,
            self._exfiltration,
            self._injection_content,
        )

    @property
    def config(self) -> DetectionConfig:
        return self._config

    def evaluate(self, profile: AgentProfile, event: AgentEvent) -> list[Signal]:
        mature = profile.mature(self._config)
        signals: list[Signal] = []
        for detector in self._detectors:
            signals.extend(detector(profile, event, mature))
        return signals

    # ------------------------------------------------------------------ helpers

    @staticmethod
    def _signal(
        event: AgentEvent,
        *,
        detector: str,
        title: str,
        description: str,
        severity: Severity,
        score: float,
        discriminator: str = "",
        techniques: tuple[Technique, ...] = (),
        evidence: dict[str, Any] | None = None,
    ) -> Signal:
        return Signal(
            detector=detector,
            rule_id=detector,
            title=title,
            description=description,
            severity=severity,
            score=round(min(max(score, 0.0), 1.0), 4),
            discriminator=discriminator,
            techniques=techniques,
            evidence=evidence or {},
            event_id=event.event_id,
            agent_id=event.agent_id,
            observed_at=event.timestamp,
        )

    # ---------------------------------------------------------------- sequence

    def _sequence(self, profile: AgentProfile, event: AgentEvent, mature: bool) -> list[Signal]:
        if event.kind not in SEQUENCE_KINDS or not mature:
            return []
        subject = event.subject
        cfg = self._config
        if subject not in profile.tools:
            mass = missing_mass(profile.tools)
            settled = mass < cfg.novelty_missing_mass
            return [
                self._signal(
                    event,
                    detector="sequence.novel_tool",
                    title="Agent used a tool outside its baseline",
                    description=f"{subject} has never been used by this agent.",
                    severity=Severity.MEDIUM if settled else Severity.LOW,
                    score=0.55 if settled else 0.3,
                    discriminator=subject,
                    techniques=(technique("AML.T0053"),),
                    evidence={
                        "tool": subject,
                        "known_tools": len(profile.tools),
                        "missing_mass": round(mass, 4),
                    },
                )
            ]
        step = profile.sequence.transition(
            subject,
            session=event.session,
            alpha=cfg.smoothing_alpha,
            min_support=cfg.min_context_support,
        )
        signals = self._sequence_window(profile, event, step.surprise)
        if step.context and step.probability < cfg.rare_transition_probability:
            surprise = step.surprise
            path = " -> ".join((*step.context, subject))
            signals.append(
                self._signal(
                    event,
                    detector="sequence.rare_transition",
                    title="Rare tool transition",
                    description=f"Transition {path} has probability {step.probability:.5f}.",
                    severity=Severity.LOW,
                    score=min(0.6, 0.15 + 0.04 * surprise),
                    discriminator=path,
                    techniques=(technique("AML.T0053"),),
                    evidence={
                        "sequence": [*step.context, subject],
                        "probability": round(step.probability, 6),
                        "surprise_bits": round(surprise, 2),
                        "context_support": step.support,
                    },
                )
            )
        return signals

    def _sequence_window(
        self, profile: AgentProfile, event: AgentEvent, surprise: float
    ) -> list[Signal]:
        cfg = self._config
        stats = profile.surprise
        recent = profile.recent_surprise.get(event.session, [])
        window = [*recent[-(cfg.sequence_window - 1) :], surprise]
        if stats.n < cfg.sequence_min_samples or len(window) < cfg.sequence_window:
            return []
        mean = sum(window) / len(window)
        z = (mean - stats.mean) / (max(stats.std, 0.5) / math.sqrt(len(window)))
        if z < cfg.sequence_window_zscore:
            return []
        return [
            self._signal(
                event,
                detector="sequence.anomalous_window",
                title="Anomalous tool sequence",
                description=f"The last {len(window)} steps average {mean:.1f} bits of "
                f"surprise against a baseline of {stats.mean:.1f} (z={z:.1f}): the agent is "
                "following a plan unlike its normal behaviour.",
                severity=Severity.MEDIUM,
                score=min(0.85, 0.5 + 0.03 * z),
                discriminator="window",
                techniques=(technique("AML.T0053"),),
                evidence={
                    "window_mean_bits": round(mean, 2),
                    "baseline_mean_bits": round(stats.mean, 2),
                    "zscore": round(z, 2),
                    "steps": len(window),
                },
            )
        ]

    # ------------------------------------------------------------- time and rate

    def _time_of_day(self, profile: AgentProfile, event: AgentEvent, mature: bool) -> list[Signal]:
        if not mature:
            return []
        hour = event.timestamp.hour
        probability = profile.hour_probability(hour)
        if probability >= self._config.off_hours_probability:
            return []
        # One signal per agent per hour: an off-hours session is one anomaly,
        # not one per event.
        if profile.window_prune("off_hours", event.timestamp, span_s=3600):
            return []
        profile.window_add("off_hours", event.timestamp, str(hour), span_s=3600)
        return [
            self._signal(
                event,
                detector="time.off_hours",
                title="Activity outside the agent's normal hours",
                description=f"Activity at {hour:02d}:00 UTC has baseline probability "
                f"{probability:.4f}.",
                severity=Severity.LOW,
                score=0.25,
                discriminator=str(hour),
                techniques=(technique("T1078"),),
                evidence={"hour_utc": hour, "probability": round(probability, 6)},
            )
        ]

    def _rate(self, profile: AgentProfile, event: AgentEvent, mature: bool) -> list[Signal]:
        minute = int(event.timestamp.timestamp() // 60)
        count = profile.minute_count + 1 if profile.minute == minute else 1
        stats = profile.rate
        if not mature or stats.n < 30:
            return []
        threshold = max(
            stats.mean + self._config.rate_spike_sigma * max(stats.std, 1.0),
            float(self._config.rate_spike_min_count),
        )
        # Fire once, on the event that crosses the threshold within the minute.
        if count < threshold or count - 1 >= threshold:
            return []
        return [
            self._signal(
                event,
                detector="frequency.rate_spike",
                title="Activity rate spike",
                description=f"{count} events in one minute against a baseline of "
                f"{stats.mean:.1f} +/- {stats.std:.1f}.",
                severity=Severity.MEDIUM,
                score=0.6,
                discriminator=str(minute),
                techniques=(technique("T1213"),),
                evidence={"events_in_minute": count, "baseline_mean": round(stats.mean, 2)},
            )
        ]

    # --------------------------------------------------------------- privilege

    def _privilege(self, profile: AgentProfile, event: AgentEvent, mature: bool) -> list[Signal]:
        cfg = self._config
        signals: list[Signal] = []
        if event.kind is EventKind.AUTHORIZATION and event.outcome is Outcome.DENIED:
            entries = profile.window_prune(
                "denials", event.timestamp, span_s=cfg.denial_burst_window_s
            )
            count = len(entries) + 1
            if count >= cfg.denial_burst_count:
                signals.append(
                    self._signal(
                        event,
                        detector="privilege.denial_burst",
                        title="Burst of denied authorization requests",
                        description=f"{count} denials within {cfg.denial_burst_window_s}s: the "
                        "agent is probing for permissions it does not hold.",
                        severity=Severity.HIGH,
                        score=min(0.95, 0.7 + 0.03 * (count - cfg.denial_burst_count)),
                        discriminator="burst",
                        techniques=(technique("T1548"), technique("T1078")),
                        evidence={
                            "denials": count,
                            "window_s": cfg.denial_burst_window_s,
                            "action": event.action,
                            "resource": event.resource,
                        },
                    )
                )
            elif mature and event.action not in profile.scopes:
                signals.append(
                    self._signal(
                        event,
                        detector="privilege.denied_action",
                        title="Denied request for an action outside the baseline",
                        description=f"Authorization for {event.action} was denied.",
                        severity=Severity.LOW,
                        score=0.3,
                        discriminator=event.action,
                        techniques=(technique("T1548"),),
                        evidence={"action": event.action, "resource": event.resource},
                    )
                )
        if mature and int(event.classification) > profile.max_classification:
            restricted = event.classification >= DataClassification.RESTRICTED
            signals.append(
                self._signal(
                    event,
                    detector="privilege.classification_jump",
                    title="Access above the agent's usual data classification",
                    description=f"Accessed {event.classification.name} data; baseline maximum "
                    f"is {DataClassification(profile.max_classification).name}.",
                    severity=Severity.HIGH if restricted else Severity.MEDIUM,
                    score=0.75 if restricted else 0.55,
                    discriminator=event.classification.name,
                    techniques=(technique("T1213"),),
                    evidence={
                        "classification": event.classification.name,
                        "baseline_max": DataClassification(profile.max_classification).name,
                        "resource": event.resource,
                    },
                )
            )
        novel = [s for s in event.scopes_requested if s not in profile.scopes]
        if mature and novel:
            privileged = [s for s in novel if _PRIVILEGED_SCOPE.search(s)]
            signals.append(
                self._signal(
                    event,
                    detector="privilege.scope_escalation",
                    title="Agent requested scopes outside its baseline",
                    description=f"Requested new scopes {sorted(novel)}.",
                    severity=Severity.HIGH if privileged else Severity.MEDIUM,
                    score=0.8 if privileged else 0.55,
                    discriminator=",".join(sorted(novel)),
                    techniques=(technique("T1134"), technique("T1548")),
                    evidence={"new_scopes": sorted(novel), "privileged": sorted(privileged)},
                )
            )
        return signals

    # -------------------------------------------------------------- delegation

    def _delegation(self, profile: AgentProfile, event: AgentEvent, mature: bool) -> list[Signal]:
        if event.kind is not EventKind.DELEGATION or event.delegate is None:
            return []
        cfg = self._config
        delegate = event.delegate
        chain = (*event.delegation_chain, delegate)
        signals: list[Signal] = []
        lineage = (event.agent_id, *event.delegation_chain)
        if delegate in lineage:
            signals.append(
                self._signal(
                    event,
                    detector="delegation.cycle",
                    title="Delegation cycle",
                    description=f"{delegate} already appears in the delegation chain.",
                    severity=Severity.HIGH,
                    score=0.85,
                    discriminator=delegate,
                    techniques=(technique("T1550"),),
                    evidence={"chain": list(lineage), "delegate": delegate},
                )
            )
        depth = len(chain)
        if depth > cfg.max_delegation_depth or (
            mature and depth > profile.max_delegation_depth + 1
        ):
            signals.append(
                self._signal(
                    event,
                    detector="delegation.depth",
                    title="Unusually deep delegation chain",
                    description=f"Delegation depth {depth} exceeds the expected maximum.",
                    severity=Severity.MEDIUM,
                    score=0.6,
                    discriminator=str(depth),
                    techniques=(technique("T1550"),),
                    evidence={
                        "depth": depth,
                        "baseline_max": profile.max_delegation_depth,
                        "limit": cfg.max_delegation_depth,
                    },
                )
            )
        if mature and delegate not in profile.delegates:
            mass = missing_mass(profile.delegates)
            settled = mass < cfg.novelty_missing_mass
            signals.append(
                self._signal(
                    event,
                    detector="delegation.new_delegate",
                    title="Delegation to an agent outside the baseline",
                    description=f"First delegation to {delegate}.",
                    severity=Severity.MEDIUM if settled else Severity.LOW,
                    score=0.5 if settled else 0.3,
                    discriminator=delegate,
                    techniques=(technique("T1550"),),
                    evidence={
                        "delegate": delegate,
                        "known_delegates": len(profile.delegates),
                        "missing_mass": round(mass, 4),
                    },
                )
            )
        entries = profile.window_prune(
            "delegates", event.timestamp, span_s=cfg.delegation_fanout_window_s
        )
        distinct = {value for _, value in entries} | {delegate}
        if len(distinct) >= cfg.delegation_fanout_count and delegate not in {
            value for _, value in entries
        }:
            signals.append(
                self._signal(
                    event,
                    detector="delegation.fanout",
                    title="Delegation fan-out burst",
                    description=f"Delegated to {len(distinct)} distinct agents within "
                    f"{cfg.delegation_fanout_window_s}s.",
                    severity=Severity.HIGH,
                    score=0.8,
                    discriminator="fanout",
                    techniques=(technique("T1550"),),
                    evidence={"distinct_delegates": len(distinct)},
                )
            )
        return signals

    # ------------------------------------------------------------ exfiltration

    def _exfiltration(self, profile: AgentProfile, event: AgentEvent, mature: bool) -> list[Signal]:
        if event.kind not in EGRESS_KINDS and event.kind is not EventKind.MODEL_CALL:
            return []
        cfg = self._config
        excerpt = event.content_excerpt or ""
        signals = self._outbound_content(event, excerpt) if excerpt else []
        if event.kind not in EGRESS_KINDS or not event.destination:
            return signals
        destination = event.destination
        new_destination = mature and destination not in profile.destinations
        if new_destination:
            sensitive = event.classification >= DataClassification.CONFIDENTIAL
            mass = missing_mass(profile.destinations)
            settled = mass < cfg.novelty_missing_mass
            external = cfg.is_external(destination)
            if settled or external:
                severity = Severity.HIGH if sensitive else Severity.MEDIUM
            else:
                severity = Severity.LOW
            signals.append(
                self._signal(
                    event,
                    detector="exfiltration.new_destination",
                    title="Egress to a destination outside the baseline",
                    description=f"First transfer to {destination}.",
                    severity=severity,
                    score=NOVELTY_SCORE[severity],
                    discriminator=destination,
                    techniques=(technique("T1567"), technique("T1048")),
                    evidence={
                        "destination": destination,
                        "classification": event.classification.name,
                        "bytes_out": event.bytes_out,
                        "missing_mass": round(mass, 4),
                        "external": external,
                    },
                )
            )
        if excerpt and (new_destination or not mature):
            blob = _BASE64_RUN.search(excerpt) or _HEX_RUN.search(excerpt)
            if blob and len(blob.group(0)) >= cfg.encoded_blob_min_chars:
                signals.append(
                    self._signal(
                        event,
                        detector="exfiltration.encoded_payload",
                        title="Encoded blob sent to an unfamiliar destination",
                        description="Outbound content carries a long base64 or hex run.",
                        severity=Severity.MEDIUM,
                        score=0.6,
                        discriminator=destination,
                        techniques=(technique("T1048"),),
                        evidence={"destination": destination, "blob_chars": len(blob.group(0))},
                    )
                )
        if event.bytes_out <= 0:
            return signals
        stats = profile.egress
        if mature and stats.n >= cfg.egress_min_samples:
            z = stats.zscore(math.log1p(event.bytes_out), floor=0.25)
            if z >= cfg.egress_zscore_medium:
                high = z >= cfg.egress_zscore_high
                signals.append(
                    self._signal(
                        event,
                        detector="exfiltration.volume",
                        title="Unusually large data transfer",
                        description=f"{event.bytes_out} bytes to {destination} "
                        f"(z={z:.1f} on log scale).",
                        severity=Severity.HIGH if high else Severity.MEDIUM,
                        score=0.8 if high else 0.6,
                        discriminator=destination,
                        techniques=(technique("T1030"), technique("T1567")),
                        evidence={
                            "bytes_out": event.bytes_out,
                            "zscore": round(z, 2),
                            "destination": destination,
                        },
                    )
                )
        signals.extend(self._egress_window(profile, event, mature))
        return signals

    def _outbound_content(self, event: AgentEvent, excerpt: str) -> list[Signal]:
        """Credentials and data-bearing URL beacons in content leaving the agent."""
        signals: list[Signal] = []
        kinds = sorted({f.kind for f in self._secrets.detect(excerpt)})
        if kinds:
            signals.append(
                self._signal(
                    event,
                    detector="exfiltration.credentials",
                    title="Credential material in outbound content",
                    description=f"Outbound content contains {', '.join(kinds)}.",
                    severity=Severity.CRITICAL,
                    score=0.95,
                    discriminator=",".join(kinds),
                    techniques=(technique("T1552"), technique("AML.T0057")),
                    evidence={"secret_kinds": kinds, "destination": event.destination},
                )
            )
        injected = self._injection.assess(excerpt)
        if "exfiltration_url" in injected.kinds:
            signals.append(
                self._signal(
                    event,
                    detector="exfiltration.markdown_beacon",
                    title="Data-bearing URL beacon in agent output",
                    description="Output embeds an image or link whose query string "
                    "carries templated data, a known LLM exfiltration channel.",
                    severity=Severity.HIGH,
                    score=0.85,
                    discriminator="beacon",
                    techniques=(technique("AML.T0057"), technique("T1567")),
                    evidence={"destination": event.destination},
                )
            )
        return signals

    def _egress_window(
        self, profile: AgentProfile, event: AgentEvent, mature: bool
    ) -> list[Signal]:
        """Volume per tumbling window against the agent's normal per-window volume."""
        cfg = self._config
        window = int(event.timestamp.timestamp() // cfg.egress_window_s)
        same = profile.egress_window == window
        if same and profile.egress_window_flagged:
            return []
        total = (profile.egress_window_bytes if same else 0) + event.bytes_out
        stats = profile.egress_windows
        if not mature or stats.n < cfg.egress_min_samples:
            return []
        z = stats.zscore(math.log1p(total), floor=0.25)
        if z < cfg.egress_window_zscore:
            return []
        return [
            self._signal(
                event,
                detector="exfiltration.window_volume",
                title="Sustained high-volume egress",
                description=f"{total} bytes within one {cfg.egress_window_s}s window "
                f"(z={z:.1f} against this agent's per-window volume).",
                severity=Severity.HIGH,
                score=0.8,
                discriminator=str(window),
                techniques=(technique("T1030"), technique("T1041")),
                evidence={
                    "window_bytes": total,
                    "zscore": round(z, 2),
                    "window_s": cfg.egress_window_s,
                    "destination": event.destination,
                },
            )
        ]

    # ---------------------------------------------------------------- injection

    def _injection_content(
        self, profile: AgentProfile, event: AgentEvent, mature: bool
    ) -> list[Signal]:
        if event.kind is not EventKind.CONTENT_INGEST:
            return []
        assessed = self._injection.assess(event.content_excerpt) if event.content_excerpt else None
        score = max(event.injection_score or 0.0, assessed.score if assessed else 0.0)
        if score < self._config.injection_score_threshold:
            return []
        kinds = assessed.kinds if assessed else []
        return [
            self._signal(
                event,
                detector="injection.content",
                title="Agent ingested content carrying prompt-injection markers",
                description=f"Injection score {score:.2f} ({', '.join(kinds) or 'upstream'}); "
                "subsequent behaviour is watched for a shift.",
                severity=Severity.MEDIUM if score >= 0.9 else Severity.LOW,
                score=0.5 if score >= 0.9 else 0.35,
                discriminator=event.resource or event.action,
                techniques=(technique("AML.T0051"),),
                evidence={"injection_score": round(score, 4), "markers": kinds},
            )
        ]
