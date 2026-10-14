"""Signals, alerts and containment actions."""

from __future__ import annotations

import hashlib
from datetime import datetime
from enum import IntEnum, StrEnum
from typing import Any

from agentic_core.domain.classification import Decision
from agentic_core.domain.identifiers import new_id
from pydantic import BaseModel, ConfigDict, Field


class Severity(IntEnum):
    INFORMATIONAL = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> Severity:
        return cls[value.strip().upper()]

    @property
    def label(self) -> str:
        return self.name.lower()


class Technique(BaseModel):
    """A MITRE ATT&CK or ATLAS technique with its tactic."""

    model_config = ConfigDict(frozen=True)

    uid: str
    name: str
    tactic_uid: str
    tactic_name: str


class Signal(BaseModel):
    """One detector's verdict on one event."""

    model_config = ConfigDict(frozen=True)

    detector: str = Field(description="e.g. sequence.rare_transition or sigma")
    rule_id: str
    title: str
    description: str
    severity: Severity
    score: float = Field(ge=0.0, le=1.0, description="Confidence that this is malicious")
    discriminator: str = Field(default="", description="What makes two signals the same alert")
    techniques: tuple[Technique, ...] = ()
    evidence: dict[str, Any] = Field(default_factory=dict)
    event_id: str
    agent_id: str
    observed_at: datetime

    def dedup_key(self) -> str:
        raw = f"{self.agent_id}\x1f{self.detector}\x1f{self.rule_id}\x1f{self.discriminator}"
        return hashlib.sha256(raw.encode()).hexdigest()


class AlertStatus(StrEnum):
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"

    @property
    def open(self) -> bool:
        return self in {AlertStatus.NEW, AlertStatus.ACKNOWLEDGED, AlertStatus.CONTAINED}


class EvidenceItem(BaseModel):
    model_config = ConfigDict(frozen=True)

    event_id: str
    observed_at: datetime
    detector: str
    score: float
    evidence: dict[str, Any]


MAX_EVIDENCE = 20


class Alert(BaseModel):
    """A deduplicated finding. Repeated signals with the same key update it."""

    model_config = ConfigDict(frozen=True)

    alert_id: str = Field(default_factory=new_id)
    dedup_key: str
    agent_id: str
    detector: str
    rule_id: str
    title: str
    description: str
    severity: Severity
    score: float
    status: AlertStatus = AlertStatus.NEW
    techniques: tuple[Technique, ...] = ()
    first_seen: datetime
    last_seen: datetime
    count: int = 1
    evidence: tuple[EvidenceItem, ...] = ()
    created_at: datetime
    updated_at: datetime
    resolution_note: str | None = None
    resolved_by: str | None = None
    containment_id: str | None = None
    version: int = 1

    @classmethod
    def open_from(cls, signal: Signal, *, now: datetime) -> Alert:
        return cls(
            dedup_key=signal.dedup_key(),
            agent_id=signal.agent_id,
            detector=signal.detector,
            rule_id=signal.rule_id,
            title=signal.title,
            description=signal.description,
            severity=signal.severity,
            score=signal.score,
            techniques=signal.techniques,
            first_seen=signal.observed_at,
            last_seen=signal.observed_at,
            evidence=(_evidence(signal),),
            created_at=now,
            updated_at=now,
        )

    def merge(self, signal: Signal, *, now: datetime) -> Alert:
        return self.model_copy(
            update={
                "severity": max(self.severity, signal.severity),
                "score": max(self.score, signal.score),
                "last_seen": max(self.last_seen, signal.observed_at),
                "count": self.count + 1,
                "evidence": (*self.evidence, _evidence(signal))[-MAX_EVIDENCE:],
                "updated_at": now,
                "version": self.version + 1,
            }
        )

    def with_status(
        self,
        status: AlertStatus,
        *,
        now: datetime,
        by: str | None = None,
        note: str | None = None,
    ) -> Alert:
        update: dict[str, Any] = {"status": status, "updated_at": now, "version": self.version + 1}
        if by is not None:
            update["resolved_by"] = by
        if note is not None:
            update["resolution_note"] = note
        return self.model_copy(update=update)


def _evidence(signal: Signal) -> EvidenceItem:
    return EvidenceItem(
        event_id=signal.event_id,
        observed_at=signal.observed_at,
        detector=signal.detector,
        score=signal.score,
        evidence=signal.evidence,
    )


class ContainmentStatus(StrEnum):
    PENDING_APPROVAL = "pending_approval"
    EXECUTED = "executed"
    FAILED = "failed"
    REJECTED = "rejected"
    ROLLED_BACK = "rolled_back"

    @property
    def active(self) -> bool:
        return self in {
            ContainmentStatus.PENDING_APPROVAL,
            ContainmentStatus.EXECUTED,
            ContainmentStatus.FAILED,
        }


class ContainmentAction(BaseModel):
    """Suspension of an agent through the identity fabric, with its approval trail."""

    model_config = ConfigDict(frozen=True)

    containment_id: str = Field(default_factory=new_id)
    agent_id: str
    alert_id: str
    action: str = "suspend"
    status: ContainmentStatus
    automatic: bool
    decision: Decision
    matched_rules: tuple[str, ...]
    policy_version: str
    policy_digest: str
    reason: str
    requested_by: str
    approved_by: str | None = None
    rejected_by: str | None = None
    rolled_back_by: str | None = None
    error: str | None = None
    attempts: int = 0
    created_at: datetime
    updated_at: datetime
    executed_at: datetime | None = None
    rolled_back_at: datetime | None = None
    version: int = 1

    def evolve(self, *, now: datetime, **changes: Any) -> ContainmentAction:
        return self.model_copy(update={**changes, "updated_at": now, "version": self.version + 1})


class AlertSummary(BaseModel):
    """Compact alert view for agents (MCP tools, A2A responses)."""

    model_config = ConfigDict(frozen=True)

    alert_id: str
    agent_id: str
    title: str
    detector: str
    rule_id: str
    severity: str
    score: float
    status: AlertStatus
    count: int
    first_seen: datetime
    last_seen: datetime
    techniques: list[str]
    containment_id: str | None

    @classmethod
    def of(cls, alert: Alert) -> AlertSummary:
        return cls(
            alert_id=alert.alert_id,
            agent_id=alert.agent_id,
            title=alert.title,
            detector=alert.detector,
            rule_id=alert.rule_id,
            severity=alert.severity.label,
            score=alert.score,
            status=alert.status,
            count=alert.count,
            first_seen=alert.first_seen,
            last_seen=alert.last_seen,
            techniques=[t.uid for t in alert.techniques],
            containment_id=alert.containment_id,
        )
