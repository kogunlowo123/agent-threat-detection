"""Settings, composition root, persistence edge cases, contracts, CLI and background loops."""

from __future__ import annotations

import asyncio
import io
import json
from contextlib import redirect_stdout
from datetime import timedelta
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, generate_private_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from agent_threat_detection import contracts
from agent_threat_detection.api.app import housekeeping_forever
from agent_threat_detection.detection.baseline import AgentProfile
from agent_threat_detection.domain.errors import ConflictError, NotFoundError
from agent_threat_detection.domain.findings import Alert, ContainmentStatus
from agent_threat_detection.evaluation.__main__ import main as evaluation_main
from agent_threat_detection.infrastructure.database import AlertWrite, ThreatStore
from agent_threat_detection.infrastructure.fabric import FabricClient
from agent_threat_detection.infrastructure.siem import FileSiemSink, HttpSiemSink
from agent_threat_detection.runtime.container import Container, build_container
from agent_threat_detection.security.agents import FabricAgentAuthorizer, LocalAgentAuthorizer
from tests.conftest import ROOT, START, FakeFabric, agent_uri, make_settings
from tests.unit.test_siem_and_findings import signal


def test_settings_validation(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="production"):
        make_settings(tmp_path, environment="production")
    with pytest.raises(ValidationError, match="AUDIT_KEY_FILE"):
        make_settings(tmp_path, dev_ephemeral_keys=False)
    with pytest.raises(ValidationError, match="local agent authorization"):
        make_settings(tmp_path, agent_jwks_url=None)
    with pytest.raises(ValidationError, match="must be set together"):
        make_settings(tmp_path, fabric_url="https://fabric.corp.test", fabric_client_id="x")
    with pytest.raises(ValidationError, match="SIEM_URL"):
        make_settings(tmp_path, siem_mode="http")
    key = tmp_path / "audit-2026-10.pem"
    key.write_bytes(
        Ed25519PrivateKey.generate().private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    with pytest.raises(ValidationError, match="MCP_ALLOWED_HOSTS"):
        make_settings(
            tmp_path, environment="production", dev_ephemeral_keys=False, audit_key_file=key
        )
    production = make_settings(
        tmp_path,
        environment="production",
        dev_ephemeral_keys=False,
        audit_key_file=key,
        mcp_allowed_hosts=["threat.corp.test"],
    )
    assert production.public_base == "https://threat.corp.test"
    assert not production.fabric_lifecycle_enabled


async def test_container_in_fabric_mode_with_http_siem(tmp_path: Path) -> None:
    secret = tmp_path / "secret"
    secret.write_text("s", encoding="utf-8")
    key = tmp_path / "audit-2026-10.pem"
    key.write_bytes(
        Ed25519PrivateKey.generate().private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    settings = make_settings(
        tmp_path,
        dev_ephemeral_keys=False,
        audit_key_file=key,
        fabric_url="https://fabric.corp.test",
        fabric_token_url="https://fabric.corp.test/idp/token",
        fabric_client_id="agent-threat-detection",
        fabric_client_secret_file=secret,
        agent_jwks_url=None,
        siem_mode="http",
        siem_url="https://siem.corp.test/ocsf",
    )
    fabric = FakeFabric()
    container = await build_container(settings, http=fabric.client())
    try:
        assert isinstance(container.agents, FabricAgentAuthorizer)
        assert isinstance(container.service.containment._lifecycle, FabricClient)
        assert isinstance(container.dispatcher._sink, HttpSiemSink)
    finally:
        await container.aclose()


async def test_container_rejects_non_ed25519_audit_key(tmp_path: Path) -> None:
    key = tmp_path / "audit.pem"
    key.write_bytes(
        generate_private_key(SECP256R1()).private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    with pytest.raises(ValueError, match="Ed25519"):
        await build_container(make_settings(tmp_path, dev_ephemeral_keys=False, audit_key_file=key))


async def test_default_container_wiring(container: Container, tmp_path: Path) -> None:
    assert isinstance(container.agents, LocalAgentAuthorizer)
    assert len(container.rules.rules) >= 9
    other = tmp_path / "plain"
    other.mkdir()
    plain = await build_container(make_settings(other))
    try:
        assert isinstance(plain.dispatcher._sink, FileSiemSink)
        assert plain.service.containment._lifecycle is None
    finally:
        await plain.aclose()


async def test_store_edge_cases(container: Container) -> None:
    store: ThreatStore = container.store
    with pytest.raises(NotFoundError):
        await store.get_alert("missing")
    with pytest.raises(NotFoundError):
        await store.get_containment("missing")
    assert await store.processed([]) == set()
    profile = AgentProfile.new(agent_uri(), at=START, order=3)
    await store.save_profile(profile, expected_version=0)
    assert profile.version == 1
    with pytest.raises(ConflictError):
        await store.save_profile(
            AgentProfile.new(agent_uri(), at=START, order=3), expected_version=0
        )
    with pytest.raises(ConflictError):
        await store.save_profile(profile, expected_version=7)
    assert [p.agent_id for p in await store.list_profiles(limit=10, offset=0)] == [agent_uri()]
    alert = Alert.open_from(signal(), now=START)
    await store.save_alert(AlertWrite(alert, None), now=START)
    with pytest.raises(ConflictError):
        await store.save_alert(AlertWrite(alert.merge(signal(), now=START), 99), now=START)
    found = await store.find_open_alert(alert.dedup_key, since=START - timedelta(hours=1))
    assert found == alert
    assert await store.find_open_alert(alert.dedup_key, since=START + timedelta(hours=1)) is None
    assert await store.open_alert_counts() == {3: 1}
    assert await store.list_containment(status=ContainmentStatus.EXECUTED, limit=5, offset=0) == []
    assert await store.purge_processed(START) == 0


async def test_housekeeping_loop_survives_errors(container: Container) -> None:
    calls = {"n": 0}
    original = container.store.purge_processed

    async def flaky(before: object) -> int:
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("db hiccup")
        return await original(before)  # type: ignore[arg-type]

    container.store.purge_processed = flaky  # type: ignore[method-assign]

    async def stop_after_two(_: float) -> None:
        if calls["n"] >= 2:
            raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        await housekeeping_forever(container, 900, sleep=stop_after_two)
    assert calls["n"] == 2


def test_published_contracts_are_current() -> None:
    assert contracts.main(["--check"], root=ROOT) == 0


def test_contracts_write_and_detect_staleness(tmp_path: Path) -> None:
    assert contracts.main(["--check"], root=tmp_path) == 1
    assert contracts.main([], root=tmp_path) == 0
    assert contracts.main(["--check"], root=tmp_path) == 0
    schema = json.loads((tmp_path / "schemas" / "agent-event.schema.json").read_text())
    assert schema["$schema"].endswith("2020-12/schema")
    assert "agent_id" in schema["properties"]
    openapi = json.loads((tmp_path / "docs" / "api" / "openapi.json").read_text())
    assert "/v1/events" in openapi["paths"]
    assert "/a2a" in openapi["paths"]


def test_evaluation_cli_prints_a_report() -> None:
    out = io.StringIO()
    with redirect_stdout(out):
        code = evaluation_main(
            ["--agents", "2", "--days", "6", "--episodes", "1", "--rules", str(ROOT / "rules")]
        )
    assert code == 0
    report = json.loads(out.getvalue())
    assert report["events"] > 0
    assert len(report["scenarios"]) == 8


async def test_fabric_client_against_live_style_transport() -> None:
    """The fake fabric answers like the real one; unknown paths are 404s."""
    fabric = FakeFabric()
    async with fabric.client() as http:
        response = await http.get(
            "https://fabric.corp.test/nowhere",
            headers={"Authorization": "Bearer admin-access-token"},
        )
        assert response.status_code == 404
        wrong_grant = await http.post(
            "https://fabric.corp.test/idp/token", data={"grant_type": "password"}
        )
        assert wrong_grant.status_code == 400
    assert isinstance(fabric.client(), httpx.AsyncClient)


def test_linkedin_article_length_and_required_tags() -> None:
    text = (ROOT / "docs" / "linkedin-article.md").read_text(encoding="utf-8")
    assert 2000 <= len(text) <= 2500
    for tag in ("#AgenticAI", "#AISecurity", "#Kubernetes", "#Innovation"):
        assert tag in text
    assert "github.com/kogunlowo123/agent-threat-detection" in text
