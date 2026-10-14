"""Typed client for the agent identity fabric (github.com/kogunlowo123/agent-identity-fabric).

Agent-facing calls (``/oauth2/token`` jwt-bearer, ``/oauth2/introspect``,
``/v1/authorize``) use the agent's own credential. Lifecycle calls
(``/v1/suspend``, ``/v1/reinstate``, ``GET /v1/agents/{id}``) need an
enterprise OIDC token carrying the ``agent-security-officer`` role; the
detector obtains it with the OAuth 2.0 client-credentials grant from the
enterprise identity provider and caches it until shortly before expiry.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
from agentic_core.domain.classification import DataClassification, Decision
from pydantic import BaseModel, ConfigDict, ValidationError

from agent_threat_detection.domain.errors import (
    DependencyUnavailableError,
    ForbiddenError,
    ThreatDetectionError,
    UnauthorizedError,
)

JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer"
FABRIC_SUSPENDED = frozenset({"suspended", "revoked"})


class IssuedToken(BaseModel):
    model_config = ConfigDict(frozen=True, extra="ignore")

    access_token: str
    token_type: str
    expires_in: int
    scope: str


class Introspection(BaseModel):
    """RFC 7662 response as returned by the fabric."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    active: bool
    sub: str | None = None
    scope: str | None = None
    exp: int | None = None
    act: dict[str, Any] | None = None
    agent_status: str | None = None

    @property
    def scopes(self) -> frozenset[str]:
        return frozenset((self.scope or "").split())


class AuthorizationDecision(BaseModel):
    model_config = ConfigDict(frozen=True, extra="ignore")

    decision: Decision
    agent: str
    action: str
    resource: str
    matched_rules: tuple[str, ...]
    policy_version: str
    policy_digest: str
    reason: str
    delegation_chain: tuple[str, ...]


class FabricAgent(BaseModel):
    model_config = ConfigDict(frozen=True, extra="ignore")

    agent_id: str
    status: str
    status_reason: str | None = None


class ClientCredentials:
    """OAuth 2.0 client-credentials token source (RFC 6749 section 4.4)."""

    def __init__(
        self,
        *,
        token_url: str,
        client_id: str,
        secret_file: Path,
        scope: str | None,
        client: httpx.AsyncClient,
        clock: Callable[[], float] = time.monotonic,
        refresh_margin_s: float = 60.0,
    ) -> None:
        self._token_url = token_url
        self._client_id = client_id
        self._secret_file = secret_file
        self._scope = scope
        self._client = client
        self._clock = clock
        self._margin = refresh_margin_s
        self._token: str | None = None
        self._expires_at = 0.0
        self._lock = asyncio.Lock()

    async def token(self) -> str:
        async with self._lock:
            if self._token is not None and self._clock() < self._expires_at - self._margin:
                return self._token
            # Read on every refresh so a rotated secret is picked up without a restart.
            secret = (
                await asyncio.to_thread(self._secret_file.read_text, encoding="utf-8")
            ).strip()
            form = {
                "grant_type": "client_credentials",
                "client_id": self._client_id,
                "client_secret": secret,
            }
            if self._scope:
                form["scope"] = self._scope
            try:
                response = await self._client.post(self._token_url, data=form)
            except httpx.HTTPError as exc:
                raise DependencyUnavailableError("identity provider unreachable") from exc
            if response.status_code != 200:
                raise DependencyUnavailableError(
                    f"identity provider refused client credentials ({response.status_code})"
                )
            body = response.json()
            token = body.get("access_token")
            if not isinstance(token, str) or not token:
                raise DependencyUnavailableError("identity provider returned no access token")
            self._token = token
            self._expires_at = self._clock() + float(body.get("expires_in", 300))
            return token

    def invalidate(self) -> None:
        self._token = None


class FabricClient:
    def __init__(
        self,
        base_url: str,
        *,
        client: httpx.AsyncClient,
        admin_tokens: ClientCredentials | None,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._client = client
        self._admin = admin_tokens

    async def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        try:
            response = await self._client.request(method, f"{self._base}{path}", **kwargs)
        except httpx.HTTPError as exc:
            raise DependencyUnavailableError(f"identity fabric unreachable: {exc}") from exc
        if response.status_code >= 500:
            raise DependencyUnavailableError(
                f"identity fabric error {response.status_code} on {path}"
            )
        return response

    @staticmethod
    def _parse[M: BaseModel](model: type[M], response: httpx.Response) -> M:
        try:
            return model.model_validate(response.json())
        except (ValueError, ValidationError) as exc:
            raise DependencyUnavailableError("identity fabric returned an invalid body") from exc

    @staticmethod
    def _error(response: httpx.Response) -> str:
        try:
            body = response.json()
        except ValueError:
            return f"HTTP {response.status_code}"
        if isinstance(body, dict):
            return str(body.get("error_description") or body.get("error") or body)
        return str(body)

    # ------------------------------------------------------------ agent-facing

    async def issue_token(
        self, client_id: str, assertion: str, *, scope: str | None = None
    ) -> IssuedToken:
        form = {"grant_type": JWT_BEARER, "client_id": client_id, "assertion": assertion}
        if scope:
            form["scope"] = scope
        response = await self._request("POST", "/oauth2/token", data=form)
        if response.status_code != 200:
            raise UnauthorizedError(f"credential request rejected: {self._error(response)}")
        return self._parse(IssuedToken, response)

    async def introspect(self, token: str) -> Introspection:
        response = await self._request("POST", "/oauth2/introspect", data={"token": token})
        if response.status_code != 200:
            raise DependencyUnavailableError(f"introspection failed: {self._error(response)}")
        return self._parse(Introspection, response)

    async def authorize(
        self,
        token: str,
        *,
        action: str,
        resource_type: str,
        resource_id: str = "*",
        classification: DataClassification = DataClassification.INTERNAL,
        environment: dict[str, Any] | None = None,
    ) -> AuthorizationDecision:
        response = await self._request(
            "POST",
            "/v1/authorize",
            json={
                "action": action,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "resource_classification": int(classification),
                "environment": environment or {},
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        if response.status_code == 401:
            raise UnauthorizedError("agent credential rejected by the identity fabric")
        if response.status_code != 200:
            raise ForbiddenError(f"authorization refused: {self._error(response)}")
        return self._parse(AuthorizationDecision, response)

    # --------------------------------------------------------------- lifecycle

    async def _admin_request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        if self._admin is None:
            raise DependencyUnavailableError("identity fabric administrator credentials missing")
        for attempt in range(2):
            token = await self._admin.token()
            response = await self._request(
                method, path, headers={"Authorization": f"Bearer {token}"}, **kwargs
            )
            if response.status_code == 401 and attempt == 0:
                self._admin.invalidate()  # expired or rotated upstream; fetch a fresh token once
                continue
            return response
        return response  # pragma: no cover - loop always returns

    async def get_agent(self, agent_uri: str) -> FabricAgent:
        response = await self._admin_request("GET", f"/v1/agents/{agent_uri}")
        if response.status_code != 200:
            raise ThreatDetectionError(f"agent lookup failed: {self._error(response)}")
        return self._parse(FabricAgent, response)

    async def suspend(self, agent_uri: str, *, reason: str) -> FabricAgent:
        """Suspend an agent; idempotent when it is already suspended or revoked."""
        response = await self._admin_request(
            "POST", "/v1/suspend", params={"agent_uri": agent_uri}, json={"reason": reason[:500]}
        )
        if response.status_code == 409:
            current = await self.get_agent(agent_uri)
            if current.status in FABRIC_SUSPENDED:
                return current
        if response.status_code != 200:
            raise ThreatDetectionError(f"suspension refused: {self._error(response)}")
        return self._parse(FabricAgent, response)

    async def reinstate(self, agent_uri: str, *, reason: str) -> FabricAgent:
        response = await self._admin_request(
            "POST", "/v1/reinstate", params={"agent_uri": agent_uri}, json={"reason": reason[:500]}
        )
        if response.status_code != 200:
            raise ThreatDetectionError(f"reinstatement refused: {self._error(response)}")
        return self._parse(FabricAgent, response)
