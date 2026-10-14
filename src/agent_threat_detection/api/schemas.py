"""Request and response bodies for the HTTP API."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from agent_threat_detection.application.service import Resolution
from agent_threat_detection.detection.sigma import SigmaRule
from agent_threat_detection.domain.findings import Alert, ContainmentAction, Technique


class AlertList(BaseModel):
    items: list[Alert]
    limit: int
    offset: int


class ContainmentList(BaseModel):
    items: list[ContainmentAction]
    limit: int
    offset: int


class Note(BaseModel):
    model_config = ConfigDict(extra="forbid")

    note: str = Field(min_length=3, max_length=500)


class ResolveRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    resolution: Resolution
    note: str = Field(min_length=3, max_length=500)


class RuleView(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    title: str
    description: str
    status: str
    level: str
    category: str | None
    tags: list[str]
    techniques: list[Technique]
    falsepositives: list[str]
    aggregated: bool
    timeframe_s: int | None
    source: str

    @classmethod
    def of(cls, rule: SigmaRule) -> RuleView:
        return cls(
            id=rule.id,
            title=rule.title,
            description=rule.description,
            status=rule.status,
            level=rule.level.label,
            category=rule.category.value if rule.category else None,
            tags=list(rule.tags),
            techniques=list(rule.techniques),
            falsepositives=list(rule.falsepositives),
            aggregated=rule.aggregation is not None,
            timeframe_s=rule.timeframe_s,
            source=rule.source,
        )


class RuleList(BaseModel):
    digest: str
    items: list[RuleView]


class OtlpPartialSuccess(BaseModel):
    rejectedSpans: int = 0  # noqa: N815 - OTLP/JSON field name
    errorMessage: str = ""  # noqa: N815 - OTLP/JSON field name


class OtlpExportResponse(BaseModel):
    """``ExportTraceServiceResponse`` in OTLP/JSON."""

    partialSuccess: OtlpPartialSuccess = Field(  # noqa: N815 - OTLP/JSON field name
        default_factory=OtlpPartialSuccess
    )
