"""FastAPI application factory."""

from __future__ import annotations

import asyncio
import contextlib
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from datetime import timedelta
from typing import Annotated, Any

from agentic_core.observability import bind_correlation_id, get_logger
from fastapi import FastAPI, Header, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from agent_threat_detection import __version__
from agent_threat_detection.api.routes import router
from agent_threat_detection.domain.errors import ThreatDetectionError
from agent_threat_detection.integrations import a2a
from agent_threat_detection.integrations.mcp_server import build_mcp, mcp_asgi
from agent_threat_detection.runtime.container import Container
from agent_threat_detection.security.agents import bearer_token

ContainerFactory = Callable[[], Awaitable[Container]]
OUTBOX_RETENTION = timedelta(days=7)

log = get_logger("agent_threat_detection.api")


async def housekeeping_forever(
    container: Container,
    interval_s: float,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> None:
    """Expire idempotency keys and delivered SIEM findings."""
    while True:
        try:
            now = container.clock.now()
            retention = timedelta(hours=container.settings.processed_event_retention_hours)
            await container.store.purge_processed(now - retention)
            await container.store.purge_delivered(now - OUTBOX_RETENTION)
        except Exception:
            log.exception("housekeeping_failed")
        await sleep(interval_s)


def create_app(
    factory: ContainerFactory,
    *,
    housekeeping_interval_s: float = 900.0,
    mcp_allowed_hosts: list[str] | None = None,
) -> FastAPI:
    holder: dict[str, Container] = {}

    def current() -> Container:
        return holder["container"]

    mcp = build_mcp(current)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        container = await factory()
        holder["container"] = container
        app.state.container = container
        tasks = [
            asyncio.create_task(
                container.dispatcher.run_forever(container.settings.siem_interval_seconds)
            ),
            asyncio.create_task(housekeeping_forever(container, housekeeping_interval_s)),
        ]
        log.info("startup", version=__version__, rules=len(container.rules.rules))
        try:
            async with mcp.session_manager.run():
                yield
        finally:
            for task in tasks:
                task.cancel()
            for task in tasks:
                with contextlib.suppress(asyncio.CancelledError):
                    await task
            await container.aclose()

    app = FastAPI(
        title="Agent Threat Detection",
        version=__version__,
        description=(
            "Runtime threat detection for agent ecosystems: telemetry ingestion, per-agent "
            "behavioural baselines, behavioural and Sigma-style detections, OCSF findings and "
            "approval-gated containment through the agent identity fabric."
        ),
        lifespan=lifespan,
    )
    app.include_router(router)

    @app.get("/.well-known/agent-card.json", tags=["a2a"])
    async def agent_card(request: Request) -> dict[str, Any]:
        """A2A Agent Card."""
        return a2a.agent_card(request.app.state.container)

    @app.post(
        "/a2a",
        tags=["a2a"],
        openapi_extra={
            "requestBody": {
                "required": True,
                "content": {
                    "application/json": {
                        "schema": {
                            "type": "object",
                            "description": "JSON-RPC 2.0 request, method message/send",
                            "properties": {
                                "jsonrpc": {"type": "string"},
                                "id": {},
                                "method": {"type": "string"},
                                "params": {"type": "object"},
                            },
                        }
                    }
                },
            }
        },
    )
    async def a2a_rpc(
        request: Request, authorization: Annotated[str | None, Header()] = None
    ) -> dict[str, Any]:
        """A2A JSON-RPC endpoint (``message/send``)."""
        token = bearer_token(authorization)
        return await a2a.handle(request.app.state.container, token, await request.body())

    app.mount("/mcp", mcp_asgi(mcp, allowed_hosts=mcp_allowed_hosts or []))

    @app.middleware("http")
    async def correlation_and_metrics(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        incoming = request.headers.get("x-correlation-id")
        cid = incoming if incoming and len(incoming) <= 64 and incoming.isprintable() else None
        started = time.perf_counter()
        with bind_correlation_id(cid) as bound:
            response = await call_next(request)
        response.headers["X-Correlation-ID"] = bound
        response.headers["X-Content-Type-Options"] = "nosniff"
        route = request.scope.get("route")
        path = getattr(route, "path", "unmatched")
        container: Container | None = getattr(request.app.state, "container", None)
        if container is not None:
            container.metrics.requests.labels(
                request.method, path, str(response.status_code)
            ).observe(time.perf_counter() - started)
        return response

    @app.exception_handler(ThreatDetectionError)
    async def domain_error(_: Request, exc: ThreatDetectionError) -> JSONResponse:
        headers = {"WWW-Authenticate": "Bearer"} if exc.status == 401 else None
        return JSONResponse(
            status_code=exc.status,
            content={"error": exc.code, "error_description": exc.message},
            headers=headers,
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={
                "error": "invalid_request",
                "error_description": "request failed validation",
                "details": [
                    {"loc": list(e.get("loc", ())), "msg": str(e.get("msg", ""))}
                    for e in exc.errors()
                ],
            },
        )

    return app
