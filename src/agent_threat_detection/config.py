"""Runtime settings, read from THREAT_* environment variables."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import Field, HttpUrl, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from agent_threat_detection.detection.config import DetectionConfig


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="THREAT_", env_nested_delimiter="__")

    environment: str = "production"
    public_url: HttpUrl = Field(description="Public base URL; advertised in the A2A agent card")
    database_url: str = Field(description="SQLAlchemy async URL, e.g. postgresql+asyncpg://...")

    # Audit chain (agentic-core AuditLog). The key must be Ed25519 PEM.
    audit_log_path: Path = Path("/var/lib/agent-threat-detection/audit/audit.jsonl")
    audit_key_file: Path | None = None
    dev_ephemeral_keys: bool = Field(
        default=False,
        description="Generate an in-memory audit key. Refused when environment=production.",
    )

    # Human analysts: enterprise OIDC.
    analyst_issuer: str
    analyst_audience: str
    analyst_jwks_url: str
    analyst_roles_claim: str = "roles"

    # Agent identity fabric. With fabric_url set, inbound agent calls are
    # authorized by the fabric and containment suspends agents through it.
    fabric_url: str | None = None
    fabric_token_url: str | None = Field(
        default=None, description="Enterprise IdP token endpoint for the client-credentials grant"
    )
    fabric_client_id: str | None = None
    fabric_client_secret_file: Path | None = None
    fabric_token_scope: str | None = None
    authorization_cache_seconds: float = Field(default=30.0, ge=0.0, le=300.0)

    # Local agent authorization, used only when fabric_url is unset.
    agent_jwks_url: str | None = None
    agent_issuer: str | None = None
    agent_audience: str | None = None
    inbound_policy_file: Path = Path("policies/inbound-authorization.yaml")

    # Detection and response.
    rules_dir: Path = Path("rules")
    containment_policy_file: Path = Path("policies/containment.yaml")
    auto_containment: bool = True
    protected_agents: list[str] = Field(
        default_factory=list, description="Glob patterns of agents only a human may contain"
    )
    detection: DetectionConfig = Field(default_factory=DetectionConfig)
    processed_event_retention_hours: int = Field(default=48, ge=1)

    # SIEM delivery of OCSF findings.
    siem_mode: Literal["file", "http"] = "file"
    siem_file_path: Path = Path("/var/lib/agent-threat-detection/findings/ocsf.jsonl")
    siem_url: str | None = None
    siem_format: Literal["ocsf", "splunk_hec"] = "ocsf"
    siem_token_file: Path | None = None
    siem_interval_seconds: float = Field(default=5.0, gt=0.0)

    # MCP transport: Host header values accepted (DNS-rebinding protection).
    mcp_allowed_hosts: list[str] = Field(default_factory=list)

    log_level: str = "INFO"
    otlp_endpoint: str | None = None

    @model_validator(mode="after")
    def _validate(self) -> Settings:
        if self.dev_ephemeral_keys and self.environment == "production":
            raise ValueError("dev_ephemeral_keys cannot be used in production")
        if not self.dev_ephemeral_keys and self.audit_key_file is None:
            raise ValueError("THREAT_AUDIT_KEY_FILE is required")
        if self.fabric_url:
            lifecycle = (
                self.fabric_token_url,
                self.fabric_client_id,
                self.fabric_client_secret_file,
            )
            if any(v is None for v in lifecycle) and any(v is not None for v in lifecycle):
                raise ValueError(
                    "THREAT_FABRIC_TOKEN_URL, THREAT_FABRIC_CLIENT_ID and "
                    "THREAT_FABRIC_CLIENT_SECRET_FILE must be set together"
                )
        elif not (self.agent_jwks_url and self.agent_issuer and self.agent_audience):
            raise ValueError(
                "configure THREAT_FABRIC_URL, or THREAT_AGENT_JWKS_URL, THREAT_AGENT_ISSUER and "
                "THREAT_AGENT_AUDIENCE for local agent authorization"
            )
        if self.environment == "production" and not self.mcp_allowed_hosts:
            raise ValueError("THREAT_MCP_ALLOWED_HOSTS is required in production")
        if self.siem_mode == "http" and not self.siem_url:
            raise ValueError("THREAT_SIEM_URL is required when THREAT_SIEM_MODE=http")
        return self

    @property
    def public_base(self) -> str:
        return str(self.public_url).rstrip("/")

    @property
    def fabric_lifecycle_enabled(self) -> bool:
        return bool(self.fabric_url and self.fabric_token_url)
