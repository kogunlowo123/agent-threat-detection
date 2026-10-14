"""Shared fixtures: in-process identity providers, a fake identity fabric, a service wired
to SQLite, and an app whose container is built inside its own lifespan."""

from __future__ import annotations

import json
import os
import time
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

from agent_threat_detection.api.app import create_app
from agent_threat_detection.config import Settings
from agent_threat_detection.detection.config import DetectionConfig
from agent_threat_detection.domain.errors import DependencyUnavailableError
from agent_threat_detection.domain.events import AgentEvent, EventKind
from agent_threat_detection.runtime.container import Container, build_container
from agent_threat_detection.security.jwks import StaticJwks

ROOT = Path(__file__).resolve().parents[1]
ANALYST_ISSUER = "https://login.corp.test/tenant"
AGENT_ISSUER = "https://identity.corp.test"
AGENT_AUDIENCE = "agent-platform"
TRUST = "agents.corp.test"
START = datetime(2026, 10, 5, 9, 0, tzinfo=UTC)


def agent_uri(name: str = "invoice-matcher", namespace: str = "finance") -> str:
    return f"spiffe://{TRUST}/agent/{namespace}/{name}"


@dataclass
class FakeIdp:
    """Minimal OIDC issuer: ES256 keypair plus JWKS."""

    issuer: str
    kid: str = "k1"
    key: ec.EllipticCurvePrivateKey = field(
        default_factory=lambda: ec.generate_private_key(ec.SECP256R1())
    )

    def jwks(self) -> dict[str, Any]:
        jwk = jwt.algorithms.ECAlgorithm.to_jwk(self.key.public_key(), as_dict=True)
        jwk.update({"kid": self.kid, "alg": "ES256", "use": "sig"})
        return {"keys": [jwk]}

    def mint(self, *, sub: str, aud: str, ttl: int = 300, **extra: Any) -> str:
        now = int(time.time())
        claims = {"iss": self.issuer, "sub": sub, "aud": aud, "iat": now, "exp": now + ttl}
        claims.update(extra)
        return jwt.encode(claims, self.key, algorithm="ES256", headers={"kid": self.kid})


@dataclass
class FakeClock:
    current: datetime = field(default_factory=lambda: datetime.now(UTC).replace(microsecond=0))

    def now(self) -> datetime:
        return self.current

    def advance(self, seconds: float) -> None:
        self.current += timedelta(seconds=seconds)


@dataclass
class FakeAgentStatus:
    status: str


@dataclass
class FakeLifecycle:
    """Stands in for the identity fabric's suspend/reinstate endpoints."""

    calls: list[tuple[str, str, str]] = field(default_factory=list)
    fail: bool = False

    async def suspend(self, agent_uri: str, *, reason: str) -> FakeAgentStatus:
        if self.fail:
            raise DependencyUnavailableError("identity fabric unreachable")
        self.calls.append(("suspend", agent_uri, reason))
        return FakeAgentStatus("suspended")

    async def reinstate(self, agent_uri: str, *, reason: str) -> FakeAgentStatus:
        if self.fail:
            raise DependencyUnavailableError("identity fabric unreachable")
        self.calls.append(("reinstate", agent_uri, reason))
        return FakeAgentStatus("active")


@dataclass
class FakeSink:
    findings: list[dict[str, Any]] = field(default_factory=list)
    fail: bool = False

    async def send(self, findings: Any) -> None:
        if self.fail:
            raise httpx.ConnectError("siem down")
        self.findings.extend(findings)


@dataclass
class FakeFabric:
    """The identity fabric's wire behaviour (recorded shapes of its responses).

    ``tokens`` maps agent credentials to (subject, scopes); ``decisions`` maps
    actions to the decision returned by /v1/authorize.
    """

    tokens: dict[str, tuple[str, str]] = field(default_factory=dict)
    decisions: dict[str, str] = field(default_factory=dict)
    statuses: dict[str, str] = field(default_factory=dict)
    admin_token: str = "admin-access-token"
    requests: list[httpx.Request] = field(default_factory=list)
    down: bool = False

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.down:
            raise httpx.ConnectError("fabric down", request=request)
        routes = {
            "/idp/token": self._idp_token,
            "/oauth2/introspect": self._introspect,
            "/v1/authorize": self._authorize,
        }
        route = routes.get(request.url.path)
        return route(request) if route else self._admin(request)

    def _idp_token(self, request: httpx.Request) -> httpx.Response:
        form = parse_qs(request.content.decode())
        if form.get("grant_type") != ["client_credentials"]:
            return httpx.Response(400, json={"error": "unsupported_grant_type"})
        return httpx.Response(200, json={"access_token": self.admin_token, "expires_in": 600})

    def _introspect(self, request: httpx.Request) -> httpx.Response:
        token = parse_qs(request.content.decode()).get("token", [""])[0]
        if token not in self.tokens:
            return httpx.Response(200, json={"active": False})
        sub, scope = self.tokens[token]
        return httpx.Response(
            200,
            json={
                "active": True,
                "sub": sub,
                "scope": scope,
                "exp": int(time.time()) + 300,
                "agent_status": "active",
            },
        )

    def _authorize(self, request: httpx.Request) -> httpx.Response:
        token = request.headers.get("authorization", "")[7:]
        if token not in self.tokens:
            return httpx.Response(401, json={"error": "unauthorized"})
        body = json.loads(request.content)
        sub, scope = self.tokens[token]
        decision = self.decisions.get(
            body["action"], "allow" if body["action"] in scope.split() else "deny"
        )
        return httpx.Response(
            200,
            json={
                "decision": decision,
                "agent": sub,
                "action": body["action"],
                "resource": f"{body['resource_type']}:{body['resource_id']}",
                "matched_rules": ["allow-scoped-actions"],
                "policy_version": "2026.10.0",
                "policy_digest": "sha256:" + "0" * 64,
                "reason": "explicit allow" if decision == "allow" else "denied by policy",
                "delegation_chain": [],
            },
        )

    def _admin(self, request: httpx.Request) -> httpx.Response:
        if request.headers.get("authorization") != f"Bearer {self.admin_token}":
            return httpx.Response(401, json={"error": "unauthorized"})
        path = request.url.path
        if path in {"/v1/suspend", "/v1/reinstate"}:
            uri = request.url.params.get("agent_uri", "")
            if uri not in self.statuses:
                return httpx.Response(404, json={"error": "not_found"})
            target = "suspended" if path == "/v1/suspend" else "active"
            if self.statuses[uri] == target:
                return httpx.Response(409, json={"error": "invalid_state"})
            self.statuses[uri] = target
            return httpx.Response(200, json={"agent_id": uri, "status": target})
        uri = path.removeprefix("/v1/agents/")
        if not path.startswith("/v1/agents/") or uri not in self.statuses:
            return httpx.Response(404, json={"error": "not_found"})
        return httpx.Response(200, json={"agent_id": uri, "status": self.statuses[uri]})

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            transport=httpx.MockTransport(self.handler), base_url="https://fabric.corp.test"
        )


# ---------------------------------------------------------------------- fixtures


@pytest.fixture
def analyst_idp() -> FakeIdp:
    return FakeIdp(ANALYST_ISSUER, kid="analyst-1")


@pytest.fixture
def agent_idp() -> FakeIdp:
    return FakeIdp(AGENT_ISSUER, kid="fabric-2026-10")


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def lifecycle() -> FakeLifecycle:
    return FakeLifecycle()


@pytest.fixture
def sink() -> FakeSink:
    return FakeSink()


TEST_DETECTION = DetectionConfig(
    baseline_min_events=60,
    baseline_min_hours=1.0,
    sequence_min_samples=40,
    egress_min_samples=10,
    internal_domain_suffixes=("corp.internal",),
)


def make_settings(tmp_path: Path, **overrides: Any) -> Settings:
    db = os.environ.get("THREAT_TEST_DATABASE_URL", f"sqlite+aiosqlite:///{tmp_path / 't.db'}")
    values: dict[str, Any] = {
        "environment": "test",
        "public_url": "https://threat.corp.test",
        "database_url": db,
        "dev_ephemeral_keys": True,
        "audit_log_path": tmp_path / "audit.jsonl",
        "analyst_issuer": ANALYST_ISSUER,
        "analyst_audience": "agent-threat-detection",
        "analyst_jwks_url": "https://unused.invalid/analyst-jwks",
        "agent_jwks_url": "https://unused.invalid/agent-jwks",
        "agent_issuer": AGENT_ISSUER,
        "agent_audience": AGENT_AUDIENCE,
        "rules_dir": ROOT / "rules",
        "containment_policy_file": ROOT / "policies" / "containment.yaml",
        "inbound_policy_file": ROOT / "policies" / "inbound-authorization.yaml",
        "siem_file_path": tmp_path / "ocsf.jsonl",
        "protected_agents": [f"spiffe://{TRUST}/agent/platform/*"],
        "detection": TEST_DETECTION,
    }
    values.update(overrides)
    return Settings(**values)


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return make_settings(tmp_path)


@pytest.fixture
async def container(
    *,
    settings: Settings,
    analyst_idp: FakeIdp,
    agent_idp: FakeIdp,
    lifecycle: FakeLifecycle,
    sink: FakeSink,
    clock: FakeClock,
) -> AsyncIterator[Container]:
    built = await build_container(
        settings,
        analyst_resolver=StaticJwks(analyst_idp.jwks()),
        agent_resolver=StaticJwks(agent_idp.jwks()),
        lifecycle=lifecycle,
        sink=sink,
        clock=clock,
    )
    yield built
    await built.aclose()


@pytest.fixture
def client(
    *,
    settings: Settings,
    analyst_idp: FakeIdp,
    agent_idp: FakeIdp,
    lifecycle: FakeLifecycle,
    sink: FakeSink,
    clock: FakeClock,
) -> Iterator[TestClient]:
    """App whose container is built inside the app's own event loop by its lifespan."""

    async def factory() -> Container:
        return await build_container(
            settings,
            analyst_resolver=StaticJwks(analyst_idp.jwks()),
            agent_resolver=StaticJwks(agent_idp.jwks()),
            lifecycle=lifecycle,
            sink=sink,
            clock=clock,
        )

    with TestClient(create_app(factory, mcp_allowed_hosts=["testserver"])) as test_client:
        yield test_client


# ----------------------------------------------------------------------- helpers

ALL_SCOPES = "telemetry:write threat:read containment:request"


def agent_token(idp: FakeIdp, sub: str | None = None, scope: str = ALL_SCOPES, **extra: Any) -> str:
    return idp.mint(
        sub=sub or agent_uri("soc-copilot", "security"), aud=AGENT_AUDIENCE, scope=scope, **extra
    )


def agent_headers(idp: FakeIdp, scope: str = ALL_SCOPES, **extra: Any) -> dict[str, str]:
    return {"Authorization": f"Bearer {agent_token(idp, scope=scope, **extra)}"}


def analyst_headers(idp: FakeIdp, *roles: str, sub: str = "alice@corp.test") -> dict[str, str]:
    token = idp.mint(sub=sub, aud="agent-threat-detection", roles=list(roles))
    return {"Authorization": f"Bearer {token}"}


_counter = {"n": 0}


def event(
    kind: EventKind = EventKind.TOOL_CALL,
    *,
    agent: str | None = None,
    at: datetime | None = None,
    action: str = "ledger.query",
    **fields: Any,
) -> AgentEvent:
    _counter["n"] += 1
    data: dict[str, Any] = {
        "event_id": f"evt-{_counter['n']}",
        "agent_id": agent or agent_uri(),
        "timestamp": at or START,
        "kind": kind,
        "action": action,
    }
    if kind in {EventKind.TOOL_CALL, EventKind.DATA_TRANSFER, EventKind.CONTENT_INGEST}:
        data.setdefault("tool", action)
    data.update(fields)
    return AgentEvent.model_validate(data)


CYCLE = ("ledger.query", "invoice.read", "invoice.match", "payment.schedule")


def baseline_events(
    count: int = 400,
    *,
    agent: str | None = None,
    start: datetime = START,
    step_s: int = 45,
    session: str = "s-baseline",
) -> list[AgentEvent]:
    """A deterministic, regular agent: a four-tool cycle plus periodic egress and delegation."""
    out: list[AgentEvent] = []
    for i in range(count):
        at = start + timedelta(seconds=i * step_s)
        if i % 10 == 9:
            out.append(
                event(
                    EventKind.DATA_TRANSFER,
                    agent=agent,
                    at=at,
                    action="http.post",
                    destination="erp-api.corp.internal",
                    bytes_out=4000 + (i % 7) * 100,
                    session_id=session,
                )
            )
        elif i % 25 == 24:
            out.append(
                event(
                    EventKind.DELEGATION,
                    agent=agent,
                    at=at,
                    action="token.exchange",
                    delegate=agent_uri("fx-worker", "workers"),
                    session_id=session,
                )
            )
        else:
            out.append(event(agent=agent, at=at, action=CYCLE[i % 4], session_id=session))
    return out
