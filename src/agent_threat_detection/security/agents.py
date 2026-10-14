"""Authorization of inbound calls made by agents and telemetry collectors.

With the identity fabric configured, each call is checked by the fabric
itself: ``/oauth2/introspect`` confirms the credential is live (revocation,
suspension epochs, delegation chain) and ``/v1/authorize`` returns the policy
decision. Allow decisions are cached briefly (default 30 s, never beyond the
token's expiry) because telemetry collectors call at high rates.

Without the fabric, credentials are verified locally against a configured
JWKS and evaluated by a local agentic-core ``PolicyEngine``. There is no
"allow all" mode: one of the two must be configured.
"""

from __future__ import annotations

import fnmatch
import hashlib
import time
from collections import OrderedDict
from collections.abc import Callable
from typing import Protocol

from agentic_core.domain.classification import Decision
from agentic_core.policy import PolicyEngine, PolicyRequest, Resource, Subject
from pydantic import BaseModel, ConfigDict

from agent_threat_detection.domain.errors import (
    ApprovalRequiredError,
    ForbiddenError,
    UnauthorizedError,
)
from agent_threat_detection.infrastructure.fabric import FabricClient
from agent_threat_detection.security.jwks import KeyResolver, verify_jwt


class AgentPrincipal(BaseModel):
    model_config = ConfigDict(frozen=True)

    subject: str
    scopes: frozenset[str]
    delegated: bool
    decided_by: str
    policy_digest: str


class AgentAuthorizer(Protocol):
    async def authorize(
        self, token: str, *, action: str, resource_type: str, resource_id: str = "*"
    ) -> AgentPrincipal: ...


def bearer_token(authorization: str | None) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise UnauthorizedError("agent bearer token required")
    token = authorization[7:].strip()
    if not token:
        raise UnauthorizedError("agent bearer token required")
    return token


def _raise_for(decision: Decision, reason: str) -> None:
    if decision is Decision.DENY:
        raise ForbiddenError(f"denied: {reason}")
    if decision is Decision.REQUIRE_APPROVAL:
        raise ApprovalRequiredError(f"human approval required: {reason}")


class FabricAgentAuthorizer:
    def __init__(
        self,
        fabric: FabricClient,
        *,
        cache_ttl_s: float = 30.0,
        max_entries: int = 10_000,
        clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
    ) -> None:
        self._fabric = fabric
        self._ttl = cache_ttl_s
        self._max = max_entries
        self._clock = clock
        self._wall = wall_clock
        self._cache: OrderedDict[tuple[str, str, str, str], tuple[float, AgentPrincipal]] = (
            OrderedDict()
        )

    async def authorize(
        self, token: str, *, action: str, resource_type: str, resource_id: str = "*"
    ) -> AgentPrincipal:
        key = (hashlib.sha256(token.encode()).hexdigest(), action, resource_type, resource_id)
        now = self._clock()
        cached = self._cache.get(key)
        if cached is not None and cached[0] > now:
            self._cache.move_to_end(key)
            return cached[1]
        self._cache.pop(key, None)
        introspection = await self._fabric.introspect(token)
        if not introspection.active or not introspection.sub:
            raise UnauthorizedError("agent credential is not active")
        decision = await self._fabric.authorize(
            token, action=action, resource_type=resource_type, resource_id=resource_id
        )
        _raise_for(decision.decision, decision.reason)
        principal = AgentPrincipal(
            subject=decision.agent,
            scopes=introspection.scopes,
            delegated=bool(decision.delegation_chain),
            decided_by="identity-fabric",
            policy_digest=decision.policy_digest,
        )
        lifetime = self._ttl
        if introspection.exp is not None:
            lifetime = min(lifetime, introspection.exp - self._wall())
        if lifetime > 0:
            self._cache[key] = (now + lifetime, principal)
            while len(self._cache) > self._max:
                self._cache.popitem(last=False)
        return principal


class LocalAgentAuthorizer:
    def __init__(
        self,
        resolver: KeyResolver,
        *,
        issuer: str,
        audience: str,
        policy: PolicyEngine,
    ) -> None:
        self._resolver = resolver
        self._issuer = issuer
        self._audience = audience
        self._policy = policy

    async def authorize(
        self, token: str, *, action: str, resource_type: str, resource_id: str = "*"
    ) -> AgentPrincipal:
        claims = await verify_jwt(
            token, self._resolver, issuer=self._issuer, audience=self._audience
        )
        raw_scope = claims.get("scope", "")
        scopes = frozenset(raw_scope.split()) if isinstance(raw_scope, str) else frozenset()
        delegated = isinstance(claims.get("act"), dict)
        decision = self._policy.evaluate(
            PolicyRequest(
                subject=Subject(
                    id=str(claims["sub"]),
                    kind="agent",
                    attributes={
                        "scopes": sorted(scopes),
                        "delegated": delegated,
                        "action_in_scope": any(fnmatch.fnmatchcase(action, s) for s in scopes),
                    },
                ),
                action=action,
                resource=Resource(type=resource_type, id=resource_id),
            )
        )
        _raise_for(decision.decision, decision.reason)
        return AgentPrincipal(
            subject=str(claims["sub"]),
            scopes=scopes,
            delegated=delegated,
            decided_by="local-policy",
            policy_digest=decision.policy_digest,
        )
