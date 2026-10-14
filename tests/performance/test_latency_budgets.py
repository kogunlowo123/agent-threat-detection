"""Latency and throughput budgets for hot paths. Loose enough for shared CI runners."""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from agent_threat_detection.detection.detectors import BehaviouralDetectors
from agent_threat_detection.detection.pipeline import DetectionPipeline
from agent_threat_detection.detection.sigma import RuleSet
from agent_threat_detection.evaluation.simulator import TraceConfig, TraceGenerator
from tests.conftest import ROOT, TEST_DETECTION, FakeIdp, agent_headers, baseline_events

pytestmark = pytest.mark.performance


def test_pipeline_throughput() -> None:
    """Pure detection cost per event, all detectors and rules enabled."""
    trace = TraceGenerator(
        TraceConfig(agents=6, days=5, episodes_per_scenario=1, seed=7)
    ).generate()
    pipeline = DetectionPipeline(
        BehaviouralDetectors(TEST_DETECTION), RuleSet.from_directory(ROOT / "rules")
    )
    profiles = {}
    started = time.perf_counter()
    for item in trace:
        e = item.event
        profile = profiles.get(e.agent_id)
        if profile is None:
            profile = profiles[e.agent_id] = pipeline.new_profile(e.agent_id, e.timestamp)
        pipeline.process(profile, e)
    per_event_ms = (time.perf_counter() - started) * 1000 / len(trace)
    assert len(trace) > 5000
    # About 0.3 ms uninstrumented; the suite runs under branch-coverage tracing,
    # which costs several times that, so the gate is set for shared CI runners.
    assert per_event_ms < 6.0, per_event_ms


def test_http_batch_ingest_budget(client: TestClient, agent_idp: FakeIdp) -> None:
    """A 200-event batch end to end (auth, detection, SQLite commit, audit) within budget."""
    headers = agent_headers(agent_idp, scope="telemetry:write")
    events = [e.model_dump(mode="json", exclude_none=True) for e in baseline_events(1000)]
    timings = []
    for start in range(0, 1000, 200):
        started = time.perf_counter()
        response = client.post(
            "/v1/events", json={"events": events[start : start + 200]}, headers=headers
        )
        timings.append(time.perf_counter() - started)
        assert response.status_code == 200
    assert max(timings) < 3.0, timings
