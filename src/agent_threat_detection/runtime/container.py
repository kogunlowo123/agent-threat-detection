"""Composition root: builds every dependency once per process from Settings."""

from __future__ import annotations

from dataclasses import dataclass

import httpx
from agentic_core.audit import AuditLog, JsonlAuditSink
from agentic_core.policy import PolicyEngine, PolicySet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy.ext.asyncio import AsyncEngine

from agent_threat_detection.application.containment import ContainmentService
from agent_threat_detection.application.service import ThreatDetectionService
from agent_threat_detection.config import Settings
from agent_threat_detection.detection.detectors import BehaviouralDetectors
from agent_threat_detection.detection.pipeline import DetectionPipeline
from agent_threat_detection.detection.sigma import RuleSet
from agent_threat_detection.domain.ports import AgentLifecycle, Clock
from agent_threat_detection.infrastructure.database import (
    SystemClock,
    ThreatStore,
    create_schema,
    make_engine,
)
from agent_threat_detection.infrastructure.fabric import ClientCredentials, FabricClient
from agent_threat_detection.infrastructure.siem import (
    FileSiemSink,
    HttpSiemSink,
    SiemDispatcher,
    SiemSink,
)
from agent_threat_detection.observability.metrics import ThreatMetrics
from agent_threat_detection.security.agents import (
    AgentAuthorizer,
    FabricAgentAuthorizer,
    LocalAgentAuthorizer,
)
from agent_threat_detection.security.analysts import AnalystAuthenticator
from agent_threat_detection.security.jwks import KeyResolver, RemoteJwks


@dataclass
class Container:
    settings: Settings
    service: ThreatDetectionService
    analysts: AnalystAuthenticator
    agents: AgentAuthorizer
    dispatcher: SiemDispatcher
    metrics: ThreatMetrics
    engine: AsyncEngine
    store: ThreatStore
    http: httpx.AsyncClient
    clock: Clock
    rules: RuleSet
    audit: AuditLog

    async def aclose(self) -> None:
        await self.http.aclose()
        await self.engine.dispose()


def _audit_signer(settings: Settings) -> tuple[Ed25519PrivateKey, str]:
    if settings.audit_key_file is None:
        return Ed25519PrivateKey.generate(), "audit-ephemeral"
    key = serialization.load_pem_private_key(settings.audit_key_file.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("audit key must be Ed25519")
    return key, settings.audit_key_file.stem


def _required[T](value: T | None, name: str) -> T:
    if value is None:
        raise ValueError(f"{name} is required")
    return value


def _sink(settings: Settings, http: httpx.AsyncClient) -> SiemSink:
    if settings.siem_mode == "http":
        return HttpSiemSink(
            _required(settings.siem_url, "THREAT_SIEM_URL"),
            token_file=settings.siem_token_file,
            fmt=settings.siem_format,
            client=http,
        )
    return FileSiemSink(settings.siem_file_path)


async def build_container(
    settings: Settings,
    *,
    analyst_resolver: KeyResolver | None = None,
    agent_resolver: KeyResolver | None = None,
    lifecycle: AgentLifecycle | None = None,
    sink: SiemSink | None = None,
    clock: Clock | None = None,
    http: httpx.AsyncClient | None = None,
) -> Container:
    http = http or httpx.AsyncClient(timeout=httpx.Timeout(5.0))
    clock = clock or SystemClock()
    rules = RuleSet.from_directory(settings.rules_dir)

    engine = make_engine(settings.database_url)
    await create_schema(engine)
    store = ThreatStore(engine)

    signer, key_id = _audit_signer(settings)
    audit = AuditLog(JsonlAuditSink(settings.audit_log_path), signer, key_id=key_id)

    agents: AgentAuthorizer
    fabric: FabricClient | None = None
    if settings.fabric_url:
        admin = None
        if settings.fabric_lifecycle_enabled:
            admin = ClientCredentials(
                token_url=_required(settings.fabric_token_url, "THREAT_FABRIC_TOKEN_URL"),
                client_id=_required(settings.fabric_client_id, "THREAT_FABRIC_CLIENT_ID"),
                secret_file=_required(
                    settings.fabric_client_secret_file, "THREAT_FABRIC_CLIENT_SECRET_FILE"
                ),
                scope=settings.fabric_token_scope,
                client=http,
            )
        fabric = FabricClient(settings.fabric_url, client=http, admin_tokens=admin)
        agents = FabricAgentAuthorizer(fabric, cache_ttl_s=settings.authorization_cache_seconds)
    else:
        agents = LocalAgentAuthorizer(
            agent_resolver
            or RemoteJwks(_required(settings.agent_jwks_url, "THREAT_AGENT_JWKS_URL"), client=http),
            issuer=_required(settings.agent_issuer, "THREAT_AGENT_ISSUER"),
            audience=_required(settings.agent_audience, "THREAT_AGENT_AUDIENCE"),
            policy=PolicyEngine(PolicySet.from_file(settings.inbound_policy_file)),
        )
    if lifecycle is None and fabric is not None and settings.fabric_lifecycle_enabled:
        lifecycle = fabric

    containment = ContainmentService(
        store=store,
        policy=PolicyEngine(PolicySet.from_file(settings.containment_policy_file)),
        lifecycle=lifecycle,
        audit=audit,
        clock=clock,
        protected_agents=settings.protected_agents,
        auto_containment=settings.auto_containment,
    )
    pipeline = DetectionPipeline(BehaviouralDetectors(settings.detection), rules)
    service = ThreatDetectionService(
        store=store, pipeline=pipeline, containment=containment, audit=audit, clock=clock
    )
    metrics = ThreatMetrics()
    dispatcher = SiemDispatcher(
        store, sink or _sink(settings, http), now=clock.now, on_result=metrics.siem_result
    )
    analysts = AnalystAuthenticator(
        analyst_resolver or RemoteJwks(settings.analyst_jwks_url, client=http),
        issuer=settings.analyst_issuer,
        audience=settings.analyst_audience,
        roles_claim=settings.analyst_roles_claim,
    )
    return Container(
        settings=settings,
        service=service,
        analysts=analysts,
        agents=agents,
        dispatcher=dispatcher,
        metrics=metrics,
        engine=engine,
        store=store,
        http=http,
        clock=clock,
        rules=rules,
        audit=audit,
    )
