"""Per-agent behavioural baselines.

Each agent has one ``AgentProfile`` holding everything the detectors need:

* tool-call frequency distribution,
* an n-gram Markov model of tool sequences with additive smoothing and back-off,
* data-egress volume statistics on a log scale (Welford running moments), per
  transfer and per tumbling window, so slow "drip" exfiltration that stays
  under the per-transfer threshold is still measured against the agent's
  normal volume per window,
* a 24-bin time-of-day histogram (UTC),
* known destinations, delegates and requested scopes, the highest data
  classification and delegation depth seen,
* a per-minute activity-rate model,
* sliding windows used by burst detectors and rule aggregations,
* the decayed risk score, analyst suppressions and the learning quarantine.

Profiles are plain data: they serialize to JSON for persistence and are
versioned for optimistic concurrency.
"""

from __future__ import annotations

import math
from datetime import datetime, timedelta

from pydantic import BaseModel, Field

from agent_threat_detection.detection.config import DetectionConfig

SEP = "\x1f"
MAX_CONTEXTS = 5000
MAX_WINDOW_ENTRIES = 2000
MAX_QUARANTINE_KEYS = 1000
MAX_SESSIONS = 256


def missing_mass(counts: dict[str, int]) -> float:
    """Good-Turing estimate of the probability that the next item is unseen.

    It is the share of observations that are singletons. While it is high the
    agent is still discovering new items and novelty is weak evidence.
    The add-one correction keeps a small sample (one item seen six times)
    from looking settled.
    """
    total = sum(counts.values())
    singletons = sum(1 for c in counts.values() if c == 1)
    return (singletons + 1) / (total + 1)


class RunningStats(BaseModel):
    """Welford's online mean and variance."""

    n: int = 0
    mean: float = 0.0
    m2: float = 0.0

    def update(self, value: float) -> None:
        self.n += 1
        delta = value - self.mean
        self.mean += delta / self.n
        self.m2 += delta * (value - self.mean)

    @property
    def variance(self) -> float:
        return self.m2 / (self.n - 1) if self.n > 1 else 0.0

    @property
    def std(self) -> float:
        return math.sqrt(self.variance)

    def zscore(self, value: float, *, floor: float) -> float:
        return (value - self.mean) / max(self.std, floor)


class EwStats(BaseModel):
    """Exponentially weighted mean and variance that track a slowly changing model."""

    n: int = 0
    mean: float = 0.0
    var: float = 0.0

    def update(self, value: float, *, min_alpha: float = 0.005) -> None:
        self.n += 1
        alpha = max(1.0 / self.n, min_alpha)
        delta = value - self.mean
        self.mean += alpha * delta
        self.var = (1.0 - alpha) * (self.var + alpha * delta * delta)

    @property
    def std(self) -> float:
        return math.sqrt(max(self.var, 0.0))


class Transition(BaseModel):
    probability: float
    context: tuple[str, ...]
    support: int

    @property
    def surprise(self) -> float:
        return -math.log2(self.probability)


class SequenceModel(BaseModel):
    """n-gram Markov chain over an agent's action stream.

    ``counts[context][next]`` holds transition counts for every context length
    from 0 (unigram) to ``order - 1``. Probabilities use additive (Lidstone)
    smoothing; when a context has too little support the model backs off to a
    shorter context, as in Katz back-off without discounting.

    Agents run concurrent sessions, so the recent history that forms the
    context is kept per session; the transition counts are shared.
    """

    order: int = Field(default=3, ge=2, le=6)
    counts: dict[str, dict[str, int]] = Field(default_factory=dict)
    totals: dict[str, int] = Field(default_factory=dict)
    histories: dict[str, list[str]] = Field(default_factory=dict)

    def _contexts(self, session: str) -> list[tuple[str, ...]]:
        window = self.histories.get(session, [])[-(self.order - 1) :]
        return [tuple(window[len(window) - k :]) if k else () for k in range(len(window), -1, -1)]

    def vocabulary(self) -> int:
        return len(self.counts.get("", {}))

    def transition(self, nxt: str, *, session: str, alpha: float, min_support: int) -> Transition:
        vocab = self.vocabulary() + 1
        for context in self._contexts(session):
            key = SEP.join(context)
            total = self.totals.get(key, 0)
            if total >= min_support or not context:
                count = self.counts.get(key, {}).get(nxt, 0)
                return Transition(
                    probability=(count + alpha) / (total + alpha * vocab),
                    context=context,
                    support=total,
                )
        raise AssertionError("unreachable: the empty context always matches")  # pragma: no cover

    def learn(self, nxt: str, *, session: str) -> None:
        for context in self._contexts(session):
            key = SEP.join(context)
            table = self.counts.get(key)
            if table is None:
                if len(self.counts) >= MAX_CONTEXTS:
                    continue
                table = self.counts[key] = {}
            table[nxt] = table.get(nxt, 0) + 1
            self.totals[key] = self.totals.get(key, 0) + 1
        self.advance(nxt, session=session)

    def advance(self, nxt: str, *, session: str) -> None:
        history = session_slot(self.histories, session)
        history.append(nxt)
        del history[: -(self.order - 1)]


def session_slot[T](table: dict[str, list[T]], session: str) -> list[T]:
    """Per-session list, evicting the least recently started session beyond the cap."""
    slot = table.get(session)
    if slot is None:
        if len(table) >= MAX_SESSIONS:
            del table[next(iter(table))]
        slot = table[session] = []
    return slot


class AgentProfile(BaseModel):
    agent_id: str
    created_at: datetime
    last_event_at: datetime | None = None
    events_seen: int = 0
    events_learned: int = 0
    tools: dict[str, int] = Field(default_factory=dict)
    sequence: SequenceModel = Field(default_factory=SequenceModel)
    surprise: EwStats = Field(default_factory=EwStats)
    recent_surprise: dict[str, list[float]] = Field(default_factory=dict)
    hours: list[int] = Field(default_factory=lambda: [0] * 24)
    egress: RunningStats = Field(default_factory=RunningStats)
    egress_windows: RunningStats = Field(default_factory=RunningStats)
    egress_window: int | None = None
    egress_window_bytes: int = 0
    egress_window_flagged: bool = False
    destinations: dict[str, int] = Field(default_factory=dict)
    delegates: dict[str, int] = Field(default_factory=dict)
    scopes: dict[str, int] = Field(default_factory=dict)
    max_classification: int = 0
    max_delegation_depth: int = 0
    rate: RunningStats = Field(default_factory=RunningStats)
    minute: int | None = None
    minute_count: int = 0
    windows: dict[str, list[tuple[float, str]]] = Field(default_factory=dict)
    taint_until: datetime | None = None
    taint_events_left: int = 0
    taint_event_id: str | None = None
    risk: float = 0.0
    risk_at: datetime | None = None
    suppressed: dict[str, datetime] = Field(default_factory=dict)
    quarantine: dict[str, list[str]] = Field(default_factory=dict)
    version: int = 0

    @classmethod
    def new(cls, agent_id: str, *, at: datetime, order: int) -> AgentProfile:
        return cls(agent_id=agent_id, created_at=at, sequence=SequenceModel(order=order))

    def mature(self, config: DetectionConfig) -> bool:
        if self.events_learned < config.baseline_min_events or self.last_event_at is None:
            return False
        return self.last_event_at - self.created_at >= timedelta(hours=config.baseline_min_hours)

    # ------------------------------------------------------------ sliding windows

    def window_add(self, name: str, at: datetime, value: str, *, span_s: float) -> None:
        self.windows.setdefault(name, []).append((at.timestamp(), value))
        entries = self.window_prune(name, at, span_s=span_s)
        if len(entries) > MAX_WINDOW_ENTRIES:
            del entries[: len(entries) - MAX_WINDOW_ENTRIES]

    def window_prune(self, name: str, at: datetime, *, span_s: float) -> list[tuple[float, str]]:
        entries = self.windows.get(name, [])
        cutoff = at.timestamp() - span_s
        keep = [entry for entry in entries if entry[0] > cutoff]
        if keep:
            self.windows[name] = keep
        else:
            self.windows.pop(name, None)
        return keep

    # -------------------------------------------------------------------- risk

    def decayed_risk(self, at: datetime, *, half_life_s: float) -> float:
        if self.risk_at is None or self.risk <= 0.0:
            return 0.0
        elapsed = max(0.0, (at - self.risk_at).total_seconds())
        return float(self.risk * 0.5 ** (elapsed / half_life_s))

    def hour_probability(self, hour: int) -> float:
        total = sum(self.hours)
        return (self.hours[hour] + 1) / (total + 24)

    def quarantine_days(self, keys: list[str], at: datetime) -> int:
        """Record that ``keys`` recurred today; return the fewest distinct days among them."""
        day = at.date().isoformat()
        fewest: int | None = None
        for key in keys:
            days = self.quarantine.get(key)
            if days is None:
                if len(self.quarantine) >= MAX_QUARANTINE_KEYS:
                    oldest = min(self.quarantine, key=lambda k: self.quarantine[k][-1])
                    del self.quarantine[oldest]
                days = self.quarantine[key] = []
            if day not in days:
                days.append(day)
                del days[:-31]
            fewest = len(days) if fewest is None else min(fewest, len(days))
        return fewest or 0

    def is_suppressed(self, dedup_key: str, at: datetime) -> bool:
        expiry = self.suppressed.get(dedup_key)
        return expiry is not None and expiry > at
