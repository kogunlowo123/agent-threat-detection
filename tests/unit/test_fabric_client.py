"""Typed identity-fabric client and the inbound authorizers, against the fabric's wire shapes."""

from __future__ import annotations

import time
from pathlib import Path

import httpx
import pytest
from agentic_core.policy import PolicyEngine, PolicySet

from agent_threat_detection.domain.errors import (
    ApprovalRequiredError,
    DependencyUnavailableError,
    ForbiddenError,
    ThreatDetectionError,
    UnauthorizedError,
)
from agent_threat_detection.infrastructure.fabric import ClientCredentials, FabricClient
from agent_threat_detection.security.agents import (
    FabricAgentAuthorizer,
    LocalAgentAuthorizer,
    bearer_token,
)
from agent_threat_detection.security.jwks import RemoteJwks, StaticJwks
from tests.conftest import AGENT_AUDIENCE, AGENT_ISSUER, ROOT, FakeFabric, FakeIdp, agent_uri


def credentials(
    fabric: FakeFabric, http: httpx.AsyncClient, tmp_path: Path, **kw: object
) -> ClientCredentials:
    secret = tmp_path / "secret"
    secret.write_text("client-secret\n", encoding="utf-8")
    return ClientCredentials(
        token_url="https://fabric.corp.test/idp/token",
        client_id="agent-threat-detection",
        secret_file=secret,
        scope="api://identity-fabric/.default",
        client=http,
        **kw,  # type: ignore[arg-type]
    )


async def test_lifecycle_calls(tmp_path: Path) -> None:
    fabric = FakeFabric(statuses={agent_uri(): "active"})
    async with fabric.client() as http:
        client = FabricClient(
            "https://fabric.corp.test/",
            client=http,
            admin_tokens=credentials(fabric, http, tmp_path),
        )
        suspended = await client.suspend(agent_uri(), reason="critical alert")
        assert suspended.status == "suspended"
        again = await client.suspend(agent_uri(), reason="duplicate")  # 409 -> idempotent
        assert again.status == "suspended"
        assert (await client.get_agent(agent_uri())).status == "suspended"
        assert (await client.reinstate(agent_uri(), reason="rollback")).status == "active"
        with pytest.raises(ThreatDetectionError, match="reinstatement refused"):
            await client.reinstate(agent_uri("ghost"), reason="x")
        with pytest.raises(ThreatDetectionError, match="suspension refused"):
            await client.suspend(agent_uri("ghost"), reason="x")
        with pytest.raises(ThreatDetectionError, match="agent lookup failed"):
            await client.get_agent(agent_uri("ghost"))
    token_calls = [r for r in fabric.requests if r.url.path == "/idp/token"]
    assert len(token_calls) == 1  # cached across calls
    assert b"client_secret=client-secret" in token_calls[0].content
    assert b"scope=api" in token_calls[0].content


async def test_admin_token_refreshed_once_on_401(tmp_path: Path) -> None:
    fabric = FakeFabric(statuses={agent_uri(): "active"})
    async with fabric.client() as http:
        tokens = credentials(fabric, http, tmp_path)
        client = FabricClient("https://fabric.corp.test", client=http, admin_tokens=tokens)
        await tokens.token()
        fabric.admin_token = "rotated"
        assert (await client.suspend(agent_uri(), reason="x")).status == "suspended"
    assert len([r for r in fabric.requests if r.url.path == "/idp/token"]) == 2


async def test_client_credentials_expiry_and_errors(tmp_path: Path) -> None:
    now = {"t": 0.0}
    fabric = FakeFabric()
    async with fabric.client() as http:
        tokens = credentials(fabric, http, tmp_path, clock=lambda: now["t"])
        await tokens.token()
        now["t"] = 600.0  # past expiry minus margin
        await tokens.token()
        assert len(fabric.requests) == 2

    def refuse(_: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "invalid_client"})

    def empty(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"token_type": "Bearer"})

    for handler, message in ((refuse, "refused"), (empty, "no access token")):
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            with pytest.raises(DependencyUnavailableError, match=message):
                await credentials(fabric, http, tmp_path).token()
    fabric.down = True
    async with fabric.client() as http:
        with pytest.raises(DependencyUnavailableError, match="unreachable"):
            await credentials(fabric, http, tmp_path).token()


async def test_agent_facing_calls() -> None:
    fabric = FakeFabric(tokens={"tok": (agent_uri(), "telemetry:write threat:read")})

    def issue(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/oauth2/token":
            if b"assertion=good" in request.content:
                return httpx.Response(
                    200,
                    json={
                        "access_token": "new",
                        "token_type": "Bearer",
                        "expires_in": 600,
                        "scope": "threat:read",
                        "issued_token_type": "urn:ietf:params:oauth:token-type:jwt",
                    },
                )
            return httpx.Response(400, json={"error": "invalid_grant", "error_description": "bad"})
        return fabric.handler(request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(issue)) as http:
        client = FabricClient("https://fabric.corp.test", client=http, admin_tokens=None)
        issued = await client.issue_token(agent_uri(), "good", scope="threat:read")
        assert issued.expires_in == 600
        with pytest.raises(UnauthorizedError, match="bad"):
            await client.issue_token(agent_uri(), "nope")
        intro = await client.introspect("tok")
        assert intro.active
        assert intro.scopes == {"telemetry:write", "threat:read"}
        assert not (await client.introspect("other")).active
        decision = await client.authorize("tok", action="threat:read", resource_type="alerts")
        assert decision.decision.value == "allow"
        with pytest.raises(UnauthorizedError):
            await client.authorize("other", action="threat:read", resource_type="alerts")
        with pytest.raises(DependencyUnavailableError, match="administrator credentials"):
            await client.suspend(agent_uri(), reason="x")


async def test_fabric_error_mapping() -> None:
    responses = iter(
        [
            httpx.Response(500),
            httpx.Response(200, content=b"not json"),
            httpx.Response(403, content=b"plain"),
            httpx.Response(403, json=["list"]),
            httpx.Response(400, json={"error": "invalid_request"}),
        ]
    )
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _: next(responses))) as http:
        client = FabricClient("https://fabric.corp.test", client=http, admin_tokens=None)
        with pytest.raises(DependencyUnavailableError, match="error 500"):
            await client.introspect("t")
        with pytest.raises(DependencyUnavailableError, match="invalid body"):
            await client.introspect("t")
        with pytest.raises(ForbiddenError, match="HTTP 403"):
            await client.authorize("t", action="a", resource_type="r")
        with pytest.raises(ForbiddenError, match="list"):
            await client.authorize("t", action="a", resource_type="r")
        with pytest.raises(DependencyUnavailableError, match="introspection failed"):
            await client.introspect("t")


async def test_fabric_authorizer_decisions_and_cache() -> None:
    fabric = FakeFabric(
        tokens={
            "tok": (agent_uri(), "telemetry:write threat:read"),
            "short": (agent_uri("short"), "threat:read"),
        },
        decisions={"containment:request": "require_approval"},
    )
    now = {"t": 0.0}
    async with fabric.client() as http:
        authorizer = FabricAgentAuthorizer(
            FabricClient("https://fabric.corp.test", client=http, admin_tokens=None),
            cache_ttl_s=30,
            max_entries=1,
            clock=lambda: now["t"],
        )
        principal = await authorizer.authorize("tok", action="threat:read", resource_type="alerts")
        assert principal.subject == agent_uri()
        assert principal.decided_by == "identity-fabric"
        calls = len(fabric.requests)
        await authorizer.authorize("tok", action="threat:read", resource_type="alerts")
        assert len(fabric.requests) == calls  # cached
        now["t"] = 31.0
        await authorizer.authorize("tok", action="threat:read", resource_type="alerts")
        assert len(fabric.requests) == calls + 2  # expired: introspect + authorize again
        await authorizer.authorize("short", action="threat:read", resource_type="alerts")
        assert len(authorizer._cache) == 1  # LRU bound
        with pytest.raises(ForbiddenError):
            await authorizer.authorize("tok", action="admin:everything", resource_type="alerts")
        with pytest.raises(ApprovalRequiredError):
            await authorizer.authorize("tok", action="containment:request", resource_type="alerts")
        with pytest.raises(UnauthorizedError, match="not active"):
            await authorizer.authorize("revoked", action="threat:read", resource_type="alerts")

    expired = FakeFabric(tokens={"tok": (agent_uri(), "threat:read")})
    async with expired.client() as http:
        authorizer = FabricAgentAuthorizer(
            FabricClient("https://fabric.corp.test", client=http, admin_tokens=None),
            wall_clock=lambda: time.time() + 3600,  # token already past exp: never cached
        )
        await authorizer.authorize("tok", action="threat:read", resource_type="alerts")
        assert not authorizer._cache


async def test_local_authorizer(agent_idp: FakeIdp) -> None:
    authorizer = LocalAgentAuthorizer(
        StaticJwks(agent_idp.jwks()),
        issuer=AGENT_ISSUER,
        audience=AGENT_AUDIENCE,
        policy=PolicyEngine(PolicySet.from_file(ROOT / "policies" / "inbound-authorization.yaml")),
    )
    token = agent_idp.mint(
        sub=agent_uri(), aud=AGENT_AUDIENCE, scope="threat:read containment:request"
    )
    principal = await authorizer.authorize(token, action="threat:read", resource_type="alerts")
    assert principal.decided_by == "local-policy"
    assert not principal.delegated
    with pytest.raises(ForbiddenError):
        await authorizer.authorize(token, action="telemetry:write", resource_type="telemetry")
    delegated = agent_idp.mint(
        sub=agent_uri(),
        aud=AGENT_AUDIENCE,
        scope="containment:request",
        act={"sub": agent_uri("x")},
    )
    with pytest.raises(ForbiddenError):
        await authorizer.authorize(delegated, action="containment:request", resource_type="alerts")
    weird = agent_idp.mint(sub=agent_uri(), aud=AGENT_AUDIENCE, scope=["not", "a", "string"])
    with pytest.raises(ForbiddenError):
        await authorizer.authorize(weird, action="threat:read", resource_type="alerts")


def test_bearer_token_parsing() -> None:
    assert bearer_token("Bearer abc") == "abc"
    for bad in (None, "", "Basic abc", "Bearer   "):
        with pytest.raises(UnauthorizedError):
            bearer_token(bad)


async def test_remote_jwks_caches_refreshes_and_fails_closed(agent_idp: FakeIdp) -> None:
    calls = {"n": 0, "fail": False}
    document = agent_idp.jwks()

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["fail"]:
            return httpx.Response(503)
        return httpx.Response(200, json=document)

    now = {"t": 0.0}
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        jwks = RemoteJwks(
            "https://identity.corp.test/.well-known/jwks.json",
            client=http,
            ttl_s=300,
            min_refresh_interval_s=30,
            clock=lambda: now["t"],
        )
        assert await jwks.key_for(agent_idp.kid) is not None
        await jwks.key_for(agent_idp.kid)
        assert calls["n"] == 1  # cached
        with pytest.raises(UnauthorizedError, match="unknown signing key"):
            await jwks.key_for("rotated")  # refresh rate limited: no second fetch yet
        assert calls["n"] == 1
        now["t"] = 31.0
        with pytest.raises(UnauthorizedError, match="unknown signing key"):
            await jwks.key_for("rotated")
        assert calls["n"] == 2
        now["t"] = 400.0
        calls["fail"] = True
        # Stale but issuer down: keep serving the known key, fail closed on unknown ones.
        assert await jwks.key_for(agent_idp.kid) is not None
        with pytest.raises(UnauthorizedError, match="cannot fetch"):
            await RemoteJwks("https://x.test/jwks", client=http).key_for(agent_idp.kid)
