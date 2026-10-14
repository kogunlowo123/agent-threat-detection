"""Human analyst authentication through the enterprise OIDC provider."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from agent_threat_detection.domain.errors import ForbiddenError, UnauthorizedError
from agent_threat_detection.security.jwks import KeyResolver, verify_jwt


class Analyst(BaseModel):
    model_config = ConfigDict(frozen=True)

    subject: str
    roles: frozenset[str]


class AnalystRole:
    ANALYST = "threat-analyst"  # read alerts and profiles, acknowledge, resolve
    APPROVER = "containment-approver"  # approve, reject and roll back containment
    ENGINEER = "detection-engineer"  # read rules and detection configuration


READ_ROLES = (AnalystRole.ANALYST, AnalystRole.APPROVER, AnalystRole.ENGINEER)


class AnalystAuthenticator:
    def __init__(
        self, resolver: KeyResolver, *, issuer: str, audience: str, roles_claim: str = "roles"
    ) -> None:
        self._resolver = resolver
        self._issuer = issuer
        self._audience = audience
        self._roles_claim = roles_claim

    async def authenticate(self, authorization: str | None) -> Analyst:
        if not authorization or not authorization.lower().startswith("bearer "):
            raise UnauthorizedError("bearer token required")
        claims = await verify_jwt(
            authorization[7:].strip(), self._resolver, issuer=self._issuer, audience=self._audience
        )
        raw = claims.get(self._roles_claim, [])
        roles = (
            frozenset(r for r in raw if isinstance(r, str))
            if isinstance(raw, list)
            else frozenset()
        )
        return Analyst(subject=str(claims["sub"]), roles=roles)


def require_role(analyst: Analyst, *allowed: str) -> None:
    if not analyst.roles.intersection(allowed):
        raise ForbiddenError(f"requires one of roles {sorted(allowed)}")
