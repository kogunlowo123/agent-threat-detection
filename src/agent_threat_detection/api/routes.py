"""HTTP routes.

Telemetry endpoints are called by agents and collectors with identity-fabric
credentials and are authorized per call (action ``telemetry:write``).
Analyst endpoints require an enterprise OIDC token with the right role.
"""

from __future__ import annotations

import json
import time
from typing import Annotated, Any

from agentic_core.observability import get_logger
from fastapi import APIRouter, Depends, Header, Query, Request, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from pydantic import ValidationError
from sqlalchemy import text

from agent_threat_detection.api.schemas import (
    AlertList,
    ContainmentList,
    Note,
    OtlpExportResponse,
    OtlpPartialSuccess,
    ResolveRequest,
    RuleList,
    RuleView,
)
from agent_threat_detection.application.service import AgentRiskView, IngestResult
from agent_threat_detection.domain.errors import (
    ThreatDetectionError,
    UnsupportedMediaError,
)
from agent_threat_detection.domain.events import (
    AgentEvent,
    AgentEventBatch,
    AuditBatch,
    from_audit,
    from_otlp_span,
    iter_otlp_spans,
)
from agent_threat_detection.domain.findings import (
    Alert,
    AlertStatus,
    ContainmentAction,
    ContainmentStatus,
    Severity,
)
from agent_threat_detection.infrastructure.database import AlertQuery
from agent_threat_detection.runtime.container import Container
from agent_threat_detection.security.agents import AgentPrincipal, bearer_token
from agent_threat_detection.security.analysts import (
    READ_ROLES,
    Analyst,
    AnalystRole,
    require_role,
)

router = APIRouter()
log = get_logger("agent_threat_detection.api")
MAX_OTLP_SPANS = 5000


def container(request: Request) -> Container:
    value: Container = request.app.state.container
    return value


async def analyst(
    request: Request, authorization: Annotated[str | None, Header()] = None
) -> Analyst:
    return await container(request).analysts.authenticate(authorization)


async def telemetry_writer(
    request: Request, authorization: Annotated[str | None, Header()] = None
) -> AgentPrincipal:
    c = container(request)
    try:
        principal = await c.agents.authorize(
            bearer_token(authorization), action="telemetry:write", resource_type="telemetry"
        )
    except ThreatDetectionError as exc:
        c.metrics.authorization.labels("http", exc.code).inc()
        raise
    c.metrics.authorization.labels("http", "allow").inc()
    return principal


Deps = Annotated[Container, Depends(container)]
AnalystDep = Annotated[Analyst, Depends(analyst)]
Writer = Annotated[AgentPrincipal, Depends(telemetry_writer)]


async def _ingest(
    c: Container, events: list[AgentEvent], *, source: str, actor: str, skipped: int = 0
) -> IngestResult:
    started = time.perf_counter()
    result = await c.service.ingest(events, source=source, actor=actor)
    c.metrics.ingest_latency.observe(time.perf_counter() - started)
    c.metrics.events.labels(source).inc(result.accepted)
    c.metrics.duplicates.labels(source).inc(result.duplicates)
    c.metrics.signals.labels(source).inc(result.signals)
    c.metrics.alerts.labels("open").inc(len(result.alerts_opened))
    c.metrics.alerts.labels("update").inc(len(result.alerts_updated))
    if skipped:
        c.metrics.rejected.labels(source).inc(skipped)
    return result.model_copy(update={"skipped": skipped})


# ------------------------------------------------------------------ telemetry


@router.post("/v1/events", tags=["telemetry"])
async def ingest_events(body: AgentEventBatch, c: Deps, who: Writer) -> IngestResult:
    """Native telemetry: a batch of normalized agent events."""
    return await _ingest(c, body.events, source="native", actor=who.subject)


@router.post("/v1/events/audit", tags=["telemetry"])
async def ingest_audit(body: AuditBatch, c: Deps, who: Writer) -> IngestResult:
    """agentic-core / identity-fabric audit events (non-agent actors are skipped)."""
    events = [e for e in (from_audit(r) for r in body.events) if e is not None]
    return await _ingest(
        c, events, source="audit", actor=who.subject, skipped=len(body.events) - len(events)
    )


@router.post(
    "/v1/traces",
    tags=["telemetry"],
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "description": "OTLP/JSON ExportTraceServiceRequest",
                        "properties": {"resourceSpans": {"type": "array", "items": {}}},
                    }
                }
            },
        }
    },
)
async def ingest_otlp(request: Request, c: Deps, who: Writer) -> OtlpExportResponse:
    """OTLP/HTTP trace export (JSON encoding). Point an OTel collector's otlphttp exporter here."""
    content_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
    if content_type != "application/json":
        raise UnsupportedMediaError("only OTLP/JSON (application/json) is accepted")
    try:
        document: Any = json.loads(await request.body())
    except ValueError as exc:
        raise ThreatDetectionError("body is not valid JSON") from exc
    if not isinstance(document, dict):
        raise ThreatDetectionError("body must be an ExportTraceServiceRequest object")
    events: list[AgentEvent] = []
    rejected = 0
    total = 0
    for span in iter_otlp_spans(document):
        total += 1
        if total > MAX_OTLP_SPANS:
            raise ThreatDetectionError(f"at most {MAX_OTLP_SPANS} spans per request")
        try:
            event = from_otlp_span(span)
        except (ValidationError, ThreatDetectionError, ValueError, TypeError):
            rejected += 1
            continue
        if event is not None:
            events.append(event)
    skipped = total - len(events) - rejected
    await _ingest(c, events, source="otlp", actor=who.subject, skipped=rejected)
    partial = OtlpPartialSuccess(
        rejectedSpans=rejected,
        errorMessage=(
            f"{rejected} spans could not be normalized; {skipped} spans carried no agent activity"
            if rejected
            else ""
        ),
    )
    return OtlpExportResponse(partialSuccess=partial)


# --------------------------------------------------------------------- alerts


@router.get("/v1/alerts", tags=["alerts"])
async def list_alerts(
    *,
    c: Deps,
    who: AnalystDep,
    status: Annotated[str | None, Query(pattern="^[a-z_]+$")] = None,
    agent_id: Annotated[str | None, Query(max_length=512)] = None,
    min_severity: Annotated[str, Query(pattern="^(informational|low|medium|high|critical)$")] = (
        "informational"
    ),
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> AlertList:
    require_role(who, *READ_ROLES)
    try:
        parsed = AlertStatus(status) if status else None
    except ValueError as exc:
        raise ThreatDetectionError(f"unknown status {status}") from exc
    alerts = await c.service.list_alerts(
        AlertQuery(
            status=parsed,
            agent_id=agent_id,
            min_severity=Severity.parse(min_severity),
            limit=limit,
            offset=offset,
        )
    )
    return AlertList(items=list(alerts), limit=limit, offset=offset)


@router.get("/v1/alerts/{alert_id}", tags=["alerts"])
async def get_alert(alert_id: str, c: Deps, who: AnalystDep) -> Alert:
    require_role(who, *READ_ROLES)
    return await c.service.get_alert(alert_id)


@router.post("/v1/alerts/{alert_id}/acknowledge", tags=["alerts"])
async def acknowledge(alert_id: str, body: Note, c: Deps, who: AnalystDep) -> Alert:
    require_role(who, AnalystRole.ANALYST)
    return await c.service.acknowledge(alert_id, analyst=who.subject, note=body.note)


@router.post("/v1/alerts/{alert_id}/resolve", tags=["alerts"])
async def resolve(alert_id: str, body: ResolveRequest, c: Deps, who: AnalystDep) -> Alert:
    require_role(who, AnalystRole.ANALYST)
    return await c.service.resolve(
        alert_id, resolution=body.resolution, analyst=who.subject, note=body.note
    )


@router.get("/v1/profiles", tags=["alerts"])
async def profile(
    c: Deps, who: AnalystDep, agent_id: Annotated[str, Query(min_length=10, max_length=512)]
) -> AgentRiskView:
    require_role(who, *READ_ROLES)
    return await c.service.agent_risk(agent_id)


@router.get("/v1/rules", tags=["alerts"])
async def rules(c: Deps, who: AnalystDep) -> RuleList:
    require_role(who, *READ_ROLES)
    return RuleList(digest=c.rules.digest, items=[RuleView.of(r) for r in c.rules.rules])


# ----------------------------------------------------------------- containment


@router.get("/v1/containment", tags=["containment"])
async def list_containment(
    *,
    c: Deps,
    who: AnalystDep,
    status: ContainmentStatus | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> ContainmentList:
    require_role(who, *READ_ROLES)
    items = await c.store.list_containment(status=status, limit=limit, offset=offset)
    return ContainmentList(items=list(items), limit=limit, offset=offset)


@router.get("/v1/containment/{containment_id}", tags=["containment"])
async def get_containment(containment_id: str, c: Deps, who: AnalystDep) -> ContainmentAction:
    require_role(who, *READ_ROLES)
    return await c.store.get_containment(containment_id)


def _counted(c: Container, action: ContainmentAction) -> ContainmentAction:
    c.metrics.containment.labels(action.status.value).inc()
    return action


@router.post("/v1/containment/{containment_id}/approve", tags=["containment"])
async def approve(containment_id: str, body: Note, c: Deps, who: AnalystDep) -> ContainmentAction:
    require_role(who, AnalystRole.APPROVER)
    containment = c.service.containment
    return _counted(
        c, await containment.approve(containment_id, approver=who.subject, note=body.note)
    )


@router.post("/v1/containment/{containment_id}/reject", tags=["containment"])
async def reject(containment_id: str, body: Note, c: Deps, who: AnalystDep) -> ContainmentAction:
    require_role(who, AnalystRole.APPROVER)
    containment = c.service.containment
    return _counted(
        c, await containment.reject(containment_id, approver=who.subject, note=body.note)
    )


@router.post("/v1/containment/{containment_id}/rollback", tags=["containment"])
async def rollback(containment_id: str, body: Note, c: Deps, who: AnalystDep) -> ContainmentAction:
    require_role(who, AnalystRole.APPROVER)
    containment = c.service.containment
    return _counted(
        c, await containment.rollback(containment_id, actor=who.subject, note=body.note)
    )


# ------------------------------------------------------------------ operations


@router.get("/healthz", tags=["operations"], include_in_schema=False)
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/readyz", tags=["operations"], include_in_schema=False)
async def readyz(c: Deps, response: Response) -> dict[str, str]:
    try:
        async with c.engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
    except Exception:
        response.status_code = 503
        return {"status": "database unavailable"}
    return {"status": "ready"}


@router.get("/metrics", tags=["operations"], include_in_schema=False)
async def metrics(c: Deps) -> Response:
    try:
        counts = await c.store.open_alert_counts()
        for severity in Severity:
            c.metrics.open_alerts.labels(severity.label).set(counts.get(int(severity), 0))
        c.metrics.siem_backlog.set(await c.store.outbox_backlog())
    except Exception:
        # A scrape must still succeed while the database is down; readiness reports that.
        log.warning("metrics_gauges_unavailable")
    return Response(generate_latest(c.metrics.registry), media_type=CONTENT_TYPE_LATEST)
