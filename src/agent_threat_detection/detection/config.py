"""Detection tunables.

Defaults are the values measured in docs/architecture/detection-evaluation.md.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from agent_threat_detection.domain.findings import Severity


class DetectionConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    # Baseline maturity: statistical detectors stay silent until both hold.
    baseline_min_events: int = Field(default=500, ge=10)
    baseline_min_hours: float = Field(default=72.0, ge=0.0)

    # Novelty (new tool, destination, delegate) alerts only once the agent's
    # vocabulary has stabilized: Good-Turing missing mass below this value.
    novelty_missing_mass: float = Field(default=0.02, gt=0.0, lt=1.0)

    # Sequence model.
    markov_order: int = Field(default=3, ge=2, le=6)
    smoothing_alpha: float = Field(default=0.1, gt=0.0, le=1.0)
    min_context_support: int = Field(default=20, ge=1)
    rare_transition_probability: float = Field(default=0.01, gt=0.0, lt=1.0)
    # A run of improbable steps, not one rare step, is what marks a hijacked plan:
    # mean surprise over the last ``sequence_window`` steps against the agent's own
    # per-step surprise distribution.
    sequence_window: int = Field(default=8, ge=3, le=64)
    sequence_window_zscore: float = Field(default=5.0, gt=0.0)
    sequence_min_samples: int = Field(default=200, ge=10)

    # Time of day and rate.
    off_hours_probability: float = Field(default=0.004, gt=0.0, lt=1.0)
    rate_spike_sigma: float = Field(default=6.0, gt=0.0)
    rate_spike_min_count: int = Field(default=30, ge=1)

    # Privilege escalation.
    denial_burst_count: int = Field(default=5, ge=2)
    denial_burst_window_s: int = Field(default=300, ge=10)

    # Delegation.
    max_delegation_depth: int = Field(default=3, ge=1)
    delegation_fanout_count: int = Field(default=5, ge=2)
    delegation_fanout_window_s: int = Field(default=600, ge=10)

    # Exfiltration.
    egress_min_samples: int = Field(default=30, ge=5)
    egress_zscore_medium: float = Field(default=4.0, gt=0.0)
    egress_zscore_high: float = Field(default=6.0, gt=0.0)
    egress_window_s: int = Field(default=900, ge=60)
    egress_window_zscore: float = Field(default=4.0, gt=0.0)
    encoded_blob_min_chars: int = Field(default=200, ge=32)
    # DNS suffixes of destinations inside the enterprise boundary. A first
    # transfer to a destination outside them alerts even before the agent's
    # destination set has settled. Empty: every destination is treated alike.
    internal_domain_suffixes: tuple[str, ...] = ()

    # Injection-triggered behaviour shift.
    injection_score_threshold: float = Field(default=0.5, gt=0.0, le=1.0)
    taint_events: int = Field(default=15, ge=1)
    taint_window_s: int = Field(default=900, ge=10)

    # Scoring, alerting, learning.
    # Events with LOW signals are quarantined: learned only once the same
    # anomaly key has recurred on this many distinct days. Events with
    # MEDIUM or higher signals are never learned.
    quarantine_days: int = Field(default=3, ge=1)
    alert_min_severity: Severity = Severity.MEDIUM
    risk_half_life_s: int = Field(default=3600, ge=60)
    risk_alert_threshold: float = Field(default=0.8, gt=0.0, lt=1.0)
    dedup_window_s: int = Field(default=3600, ge=60)
    suppression_days: int = Field(default=30, ge=1)

    def is_external(self, destination: str) -> bool:
        if not self.internal_domain_suffixes:
            return False
        host = destination.lower().rstrip(".")
        for suffix in self.internal_domain_suffixes:
            bare = suffix.lower().strip(".")
            if host == bare or host.endswith("." + bare):
                return False
        return True
