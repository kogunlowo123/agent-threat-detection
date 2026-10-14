"""Behavioural baseline primitives."""

from __future__ import annotations

import math
from datetime import timedelta

import pytest

from agent_threat_detection.detection import baseline as baseline_module
from agent_threat_detection.detection.baseline import (
    AgentProfile,
    EwStats,
    RunningStats,
    SequenceModel,
    missing_mass,
    session_slot,
)
from agent_threat_detection.detection.config import DetectionConfig
from tests.conftest import START, agent_uri


def test_running_stats_matches_textbook_moments() -> None:
    stats = RunningStats()
    values = [2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0]
    for v in values:
        stats.update(v)
    assert stats.mean == pytest.approx(5.0)
    assert stats.variance == pytest.approx(32 / 7)
    assert stats.zscore(5.0 + stats.std * 2, floor=0.1) == pytest.approx(2.0)
    assert RunningStats().variance == 0.0
    assert RunningStats().zscore(3.0, floor=0.5) == pytest.approx(6.0)


def test_ew_stats_track_a_shift() -> None:
    stats = EwStats()
    for _ in range(500):
        stats.update(1.0, min_alpha=0.05)
    for _ in range(200):
        stats.update(3.0, min_alpha=0.05)
    assert stats.mean == pytest.approx(3.0, abs=0.01)
    assert stats.std >= 0.0


def test_missing_mass_is_laplace_corrected() -> None:
    assert missing_mass({}) == 1.0
    assert missing_mass({"a": 6}) == pytest.approx(1 / 7)
    assert missing_mass({"a": 1, "b": 1, "c": 98}) == pytest.approx(3 / 101)


def test_sequence_model_backs_off_and_smooths() -> None:
    model = SequenceModel(order=3)
    for _ in range(30):
        for tool in ("a", "b", "c"):
            model.learn(tool, session="s")
    # Context (b, c) is well supported: a follows it every time.
    likely = model.transition("a", session="s", alpha=0.1, min_support=20)
    unlikely = model.transition("b", session="s", alpha=0.1, min_support=20)
    assert likely.context == ("b", "c")
    assert likely.probability > 0.9
    assert unlikely.probability < 0.01
    assert unlikely.surprise > 6
    # A fresh session has no history: falls back to the unigram.
    fresh = model.transition("a", session="other", alpha=0.1, min_support=20)
    assert fresh.context == ()
    assert fresh.probability == pytest.approx((30 + 0.1) / (90 + 0.1 * 4))
    # Insufficient support for long contexts backs off to shorter ones.
    sparse = model.transition("a", session="s", alpha=0.1, min_support=10_000)
    assert sparse.context == ()


def test_sequence_model_caps_contexts_and_sessions(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(baseline_module, "MAX_CONTEXTS", 3)
    monkeypatch.setattr(baseline_module, "MAX_SESSIONS", 2)
    model = SequenceModel(order=3)
    for tool in ("a", "b", "c", "d", "e"):
        model.learn(tool, session="s1")
    assert len(model.counts) == 3
    model.advance("x", session="s2")
    model.advance("y", session="s3")
    assert set(model.histories) == {"s2", "s3"}
    table: dict[str, list[int]] = {}
    session_slot(table, "a").append(1)
    session_slot(table, "b")
    session_slot(table, "c")
    assert "a" not in table


def test_profile_maturity_windows_risk_and_quarantine(monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = DetectionConfig(baseline_min_events=10, baseline_min_hours=1)
    profile = AgentProfile.new(agent_uri(), at=START, order=3)
    assert not profile.mature(cfg)
    profile.events_learned = 12
    profile.last_event_at = START + timedelta(minutes=30)
    assert not profile.mature(cfg)
    profile.last_event_at = START + timedelta(hours=2)
    assert profile.mature(cfg)

    profile.window_add("w", START, "a", span_s=60)
    profile.window_add("w", START + timedelta(seconds=30), "b", span_s=60)
    assert len(profile.window_prune("w", START + timedelta(seconds=70), span_s=60)) == 1
    assert profile.window_prune("w", START + timedelta(hours=1), span_s=60) == []
    assert "w" not in profile.windows
    monkeypatch.setattr(baseline_module, "MAX_WINDOW_ENTRIES", 3)
    for i in range(5):
        profile.window_add("big", START + timedelta(seconds=i), str(i), span_s=3600)
    assert [v for _, v in profile.windows["big"]] == ["2", "3", "4"]

    assert profile.decayed_risk(START, half_life_s=3600) == 0.0
    profile.risk, profile.risk_at = 0.8, START
    assert profile.decayed_risk(START + timedelta(hours=1), half_life_s=3600) == pytest.approx(0.4)

    assert profile.hour_probability(9) == pytest.approx(1 / 24)
    assert profile.quarantine_days(["k1", "k2"], START) == 1
    assert profile.quarantine_days(["k1"], START + timedelta(days=1)) == 2
    assert profile.quarantine_days(["k1", "k2"], START + timedelta(days=2)) == 2
    monkeypatch.setattr(baseline_module, "MAX_QUARANTINE_KEYS", 2)
    profile.quarantine_days(["k3"], START + timedelta(days=3))
    assert len(profile.quarantine) == 2

    profile.suppressed["key"] = START + timedelta(days=1)
    assert profile.is_suppressed("key", START)
    assert not profile.is_suppressed("key", START + timedelta(days=2))
    assert not profile.is_suppressed("other", START)


def test_profile_round_trips_through_json() -> None:
    profile = AgentProfile.new(agent_uri(), at=START, order=4)
    profile.sequence.learn("a", session="")
    profile.egress.update(math.log1p(100))
    profile.window_add("denials", START, "x", span_s=60)
    restored = AgentProfile.model_validate_json(profile.model_dump_json())
    assert restored == profile
