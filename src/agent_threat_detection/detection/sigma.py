"""Sigma-style detection rules for agent telemetry.

Rules use the Sigma rule layout (``title``, ``id``, ``status``, ``level``,
``logsource``, ``detection`` with named selections and a ``condition``,
``tags``, ``falsepositives``) with ``logsource.product: agent`` and
``logsource.category`` set to an ``EventKind``. Supported:

* field modifiers ``contains``, ``startswith``, ``endswith``, ``re``, ``gt``,
  ``gte``, ``lt``, ``lte``, ``exists``, ``all``, ``cased``; plain values accept
  ``*`` and ``?`` wildcards; string matching is case-insensitive unless
  ``cased`` is given;
* a selection is a mapping (all fields must match) or a list of mappings (any);
  a list of values for one field matches any value (all with ``|all``);
* conditions with ``and``, ``or``, ``not``, parentheses, ``1 of <pattern>``,
  ``all of <pattern>``, ``1 of them``, ``all of them``;
* Sigma v1 aggregations ``| count() [by <field>] <op> <n>`` and
  ``| count(<field>) [by <field>] <op> <n>`` (distinct values) over ``timeframe``.

Aggregation state lives in the agent's profile, so every aggregation is
implicitly scoped to one agent.
"""

from __future__ import annotations

import fnmatch
import hashlib
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from agent_threat_detection.detection.baseline import AgentProfile
from agent_threat_detection.detection.techniques import from_tag
from agent_threat_detection.domain.errors import RuleValidationError
from agent_threat_detection.domain.events import AgentEvent, EventKind
from agent_threat_detection.domain.findings import Severity, Signal, Technique

FIELDS = frozenset(
    {
        "event_id",
        "agent_id",
        "kind",
        "action",
        "tool",
        "resource",
        "outcome",
        "classification",
        "bytes_out",
        "destination",
        "delegate",
        "delegation_chain",
        "scopes_requested",
        "injection_score",
        "session_id",
        "hour",
        "delegation_depth",
    }
)
MODIFIERS = frozenset(
    {"contains", "startswith", "endswith", "re", "gt", "gte", "lt", "lte", "exists", "all", "cased"}
)
LEVEL_SCORE = {
    Severity.INFORMATIONAL: 0.1,
    Severity.LOW: 0.3,
    Severity.MEDIUM: 0.6,
    Severity.HIGH: 0.8,
    Severity.CRITICAL: 0.95,
}
MAX_REGEX = 512
MAX_MATCH_INPUT = 4096
_DURATION = re.compile(r"^(\d+)([smhd])$")
_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}

Matcher = Callable[[AgentEvent], bool]


def parse_timeframe(value: str) -> int:
    match = _DURATION.fullmatch(value.strip())
    if not match:
        raise RuleValidationError(f"invalid timeframe {value!r}; use e.g. 30s, 10m, 1h, 1d")
    return int(match.group(1)) * _UNITS[match.group(2)]


# ------------------------------------------------------------------ field tests


def _as_text(value: Any) -> str:
    return str(value)[:MAX_MATCH_INPUT]


def _wildcards(value: str) -> tuple[str, str | None]:
    """Split a Sigma value into its literal form and, if it has unescaped wildcards, a glob.

    ``\\*`` and ``\\?`` are literal characters; ``\\\\`` is a literal backslash.
    """
    literal: list[str] = []
    glob: list[str] = []
    wild = False
    index = 0
    while index < len(value):
        char = value[index]
        if char == "\\" and index + 1 < len(value) and value[index + 1] in "*?\\":
            nxt = value[index + 1]
            literal.append(nxt)
            glob.append(f"[{nxt}]" if nxt in "*?" else nxt)
            index += 2
            continue
        if char in "*?":
            wild = True
            glob.append(char)
        else:
            literal.append(char)
            glob.append("[[]" if char == "[" else char)
        index += 1
    return "".join(literal), ("".join(glob) if wild else None)


def _string_pattern(modifier: str | None, expected: str) -> str:
    """Regular expression equivalent of one Sigma string value under a modifier."""
    literal, glob = _wildcards(expected)
    if modifier == "contains":
        return re.escape(literal)
    if modifier == "startswith":
        return r"\A" + re.escape(literal)
    if modifier == "endswith":
        return re.escape(literal) + r"\Z"
    if glob is not None:
        return r"\A" + fnmatch.translate(glob)
    return r"\A" + re.escape(literal) + r"\Z"


def _regex_test(pattern: re.Pattern[str]) -> Callable[[Any], bool]:
    return lambda v: v is not None and pattern.search(_as_text(v)) is not None


def _numeric_test(modifier: str, expected: Any) -> Callable[[Any], bool]:
    if isinstance(expected, bool) or not isinstance(expected, int | float):
        raise RuleValidationError(f"modifier {modifier} needs a number, got {expected!r}")
    ops: dict[str, Callable[[float, float], bool]] = {
        "gt": lambda a, b: a > b,
        "gte": lambda a, b: a >= b,
        "lt": lambda a, b: a < b,
        "lte": lambda a, b: a <= b,
    }
    op = ops[modifier]

    def test(value: Any) -> bool:
        if isinstance(value, bool) or not isinstance(value, int | float):
            return False
        return op(float(value), float(expected))

    return test


def _value_test(modifiers: list[str], expected: Any) -> Callable[[Any], bool]:
    cased = "cased" in modifiers
    ops = [m for m in modifiers if m not in {"all", "cased"}]
    if len(ops) > 1:
        raise RuleValidationError(f"conflicting modifiers {ops}")
    op = ops[0] if ops else None
    if op in {"gt", "gte", "lt", "lte"}:
        return _numeric_test(op, expected)
    if op == "re":
        if not isinstance(expected, str) or len(expected) > MAX_REGEX:
            raise RuleValidationError("re modifier needs a pattern of at most 512 characters")
        try:
            pattern = re.compile(expected)
        except re.error as exc:
            raise RuleValidationError(f"invalid regular expression {expected!r}: {exc}") from exc
        return lambda v: pattern.search(_as_text(v)) is not None
    if expected is None:
        return lambda v: v is None
    if isinstance(expected, bool):
        return lambda v: v is expected
    if isinstance(expected, int | float):
        number = float(expected)
        return lambda v: (
            not isinstance(v, bool) and isinstance(v, int | float) and float(v) == number
        )
    if isinstance(expected, str):
        flags = 0 if cased else re.IGNORECASE
        return _regex_test(re.compile(_string_pattern(op, expected), flags))
    raise RuleValidationError(f"unsupported value {expected!r}")


def _field_matcher(spec: str, expected: Any) -> Matcher:
    field, *modifiers = spec.split("|")
    if field not in FIELDS and not field.startswith("attributes."):
        raise RuleValidationError(f"unknown field {field!r}")
    unknown = [m for m in modifiers if m not in MODIFIERS]
    if unknown:
        raise RuleValidationError(f"unknown modifiers {unknown} on {field}")

    if "exists" in modifiers:
        if not isinstance(expected, bool):
            raise RuleValidationError("exists modifier needs true or false")
        return lambda e: (e.field(field) not in (None, (), "")) is expected

    values = expected if isinstance(expected, list) else [expected]
    if not values:
        raise RuleValidationError(f"empty value list for {field}")
    require_all = "all" in modifiers
    ops = [m for m in modifiers if m not in {"all", "cased"}]
    op = ops[0] if len(ops) == 1 else None
    strings = [v for v in values if isinstance(v, str)]
    if not require_all and len(strings) > 1 and op not in {"re", "gt", "gte", "lt", "lte"}:
        # One compiled alternation instead of one test per value: rules run on every event.
        flags = 0 if "cased" in modifiers else re.IGNORECASE
        combined = "|".join(f"(?:{_string_pattern(op, v)})" for v in strings)
        tests = [_regex_test(re.compile(combined, flags))]
        tests.extend(_value_test(modifiers, v) for v in values if not isinstance(v, str))
    else:
        tests = [_value_test(modifiers, v) for v in values]

    def matches(event: AgentEvent) -> bool:
        actual = event.field(field)
        candidates = list(actual) if isinstance(actual, tuple | list) else [actual]
        if isinstance(actual, tuple | list) and not candidates:
            return False

        def one(test: Callable[[Any], bool]) -> bool:
            return any(test(c) for c in candidates)

        return all(one(t) for t in tests) if require_all else any(one(t) for t in tests)

    return matches


def _selection(name: str, body: Any) -> Matcher:
    if isinstance(body, Mapping):
        if not body:
            raise RuleValidationError(f"selection {name} is empty")
        parts = [_field_matcher(str(k), v) for k, v in body.items()]
        return lambda e: all(p(e) for p in parts)
    if isinstance(body, list) and body and all(isinstance(b, Mapping) for b in body):
        alternatives = [_selection(name, b) for b in body]
        return lambda e: any(a(e) for a in alternatives)
    raise RuleValidationError(f"selection {name} must be a mapping or a list of mappings")


# --------------------------------------------------------------------- conditions

_TOKEN = re.compile(r"\s*(\(|\)|\||[A-Za-z_][A-Za-z0-9_*]*|\d+|>=|<=|==|>|<)")


def _tokenize(text: str) -> list[str]:
    tokens: list[str] = []
    position = 0
    text = text.strip()
    while position < len(text):
        match = _TOKEN.match(text, position)
        if not match:
            raise RuleValidationError(f"cannot parse condition near {text[position:]!r}")
        tokens.append(match.group(1))
        position = match.end()
    return tokens


@dataclass(frozen=True)
class Aggregation:
    field: str | None
    group_by: str | None
    operator: str
    threshold: int

    def holds(self, value: int) -> bool:
        return {
            ">": value > self.threshold,
            ">=": value >= self.threshold,
            "<": value < self.threshold,
            "<=": value <= self.threshold,
            "==": value == self.threshold,
        }[self.operator]


class _Parser:
    def __init__(self, tokens: list[str], selections: Mapping[str, Matcher]) -> None:
        self._tokens = tokens
        self._pos = 0
        self._selections = selections

    def _peek(self) -> str | None:
        return self._tokens[self._pos] if self._pos < len(self._tokens) else None

    def _take(self, expected: str | None = None) -> str:
        symbol = self._peek()
        if symbol is None or (expected is not None and symbol.lower() != expected):
            raise RuleValidationError(f"expected {expected or 'token'}, found {symbol!r}")
        self._pos += 1
        return symbol

    def parse(self) -> tuple[Matcher, Aggregation | None]:
        matcher = self._or()
        aggregation = None
        if self._peek() == "|":
            self._take("|")
            aggregation = self._aggregation()
        if self._peek() is not None:
            raise RuleValidationError(f"unexpected token {self._peek()!r} in condition")
        return matcher, aggregation

    def _or(self) -> Matcher:
        parts = [self._and()]
        while (self._peek() or "").lower() == "or":
            self._take("or")
            parts.append(self._and())
        return parts[0] if len(parts) == 1 else (lambda e: any(p(e) for p in parts))

    def _and(self) -> Matcher:
        parts = [self._not()]
        while (self._peek() or "").lower() == "and":
            self._take("and")
            parts.append(self._not())
        return parts[0] if len(parts) == 1 else (lambda e: all(p(e) for p in parts))

    def _not(self) -> Matcher:
        if (self._peek() or "").lower() == "not":
            self._take("not")
            inner = self._not()
            return lambda e: not inner(e)
        return self._atom()

    def _atom(self) -> Matcher:
        symbol = self._take()
        if symbol == "(":
            inner = self._or()
            self._take(")")
            return inner
        if symbol.lower() in {"1", "any", "all"} and (self._peek() or "").lower() == "of":
            self._take("of")
            target = self._take()
            names = (
                list(self._selections)
                if target.lower() == "them"
                else [n for n in self._selections if fnmatch.fnmatchcase(n, target)]
            )
            if not names:
                raise RuleValidationError(f"no selection matches {target!r}")
            chosen = [self._selections[n] for n in names]
            if symbol.lower() == "all":
                return lambda e: all(m(e) for m in chosen)
            return lambda e: any(m(e) for m in chosen)
        if symbol in self._selections:
            return self._selections[symbol]
        raise RuleValidationError(f"condition references unknown selection {symbol!r}")

    def _aggregation(self) -> Aggregation:
        if self._take().lower() != "count":
            raise RuleValidationError("only count() aggregations are supported")
        self._take("(")
        field = None
        if self._peek() != ")":
            field = self._take()
            if field not in FIELDS and not field.startswith("attributes."):
                raise RuleValidationError(f"unknown aggregation field {field!r}")
        self._take(")")
        group_by = None
        if (self._peek() or "").lower() == "by":
            self._take("by")
            group_by = self._take()
            if group_by not in FIELDS and not group_by.startswith("attributes."):
                raise RuleValidationError(f"unknown group-by field {group_by!r}")
        operator = self._take()
        if operator not in {">", ">=", "<", "<=", "=="}:
            raise RuleValidationError(f"invalid aggregation operator {operator!r}")
        threshold = self._take()
        if not threshold.isdigit():
            raise RuleValidationError(f"aggregation threshold must be an integer, got {threshold}")
        return Aggregation(field, group_by, operator, int(threshold))


# ------------------------------------------------------------------------- rules


@dataclass(frozen=True)
class SigmaRule:
    id: str
    title: str
    description: str
    status: str
    level: Severity
    category: EventKind | None
    tags: tuple[str, ...]
    techniques: tuple[Technique, ...]
    falsepositives: tuple[str, ...]
    matcher: Matcher
    aggregation: Aggregation | None
    timeframe_s: int | None
    source: str

    @classmethod
    def parse(cls, document: Mapping[str, Any], *, source: str = "<inline>") -> SigmaRule:
        try:
            rule_id = str(document["id"])
            title = str(document["title"])
            detection = document["detection"]
            logsource = document.get("logsource") or {}
        except (KeyError, TypeError) as exc:
            raise RuleValidationError(f"{source}: missing required key {exc}") from exc
        if not re.fullmatch(r"[a-z0-9][a-z0-9\-]{2,80}", rule_id):
            raise RuleValidationError(f"{source}: rule id must be a lowercase slug")
        if logsource.get("product") != "agent":
            raise RuleValidationError(f"{source}: logsource.product must be 'agent'")
        category = logsource.get("category")
        try:
            kind = EventKind(category) if category else None
        except ValueError as exc:
            raise RuleValidationError(f"{source}: unknown logsource.category {category}") from exc
        if not isinstance(detection, Mapping) or "condition" not in detection:
            raise RuleValidationError(f"{source}: detection.condition is required")
        try:
            level = Severity.parse(str(document.get("level", "medium")))
        except KeyError as exc:
            raise RuleValidationError(f"{source}: invalid level") from exc
        selections = {
            str(name): _selection(str(name), body)
            for name, body in detection.items()
            if name not in {"condition", "timeframe"}
        }
        if not selections:
            raise RuleValidationError(f"{source}: detection has no selections")
        condition = detection["condition"]
        if not isinstance(condition, str):
            raise RuleValidationError(f"{source}: condition must be a string")
        matcher, aggregation = _Parser(_tokenize(condition), selections).parse()
        raw_timeframe = detection.get("timeframe", document.get("timeframe"))
        timeframe = parse_timeframe(str(raw_timeframe)) if raw_timeframe else None
        if aggregation is not None and timeframe is None:
            raise RuleValidationError(f"{source}: aggregations need a timeframe")
        tags = tuple(str(t) for t in document.get("tags", []) or [])
        techniques = tuple(t for t in (from_tag(tag) for tag in tags) if t is not None)
        if kind is not None:
            matcher = _scoped(kind, matcher)
        return cls(
            id=rule_id,
            title=title,
            description=str(document.get("description", title)),
            status=str(document.get("status", "experimental")),
            level=level,
            category=kind,
            tags=tags,
            techniques=techniques,
            falsepositives=tuple(str(f) for f in document.get("falsepositives", []) or []),
            matcher=matcher,
            aggregation=aggregation,
            timeframe_s=timeframe,
            source=source,
        )

    def evaluate(self, event: AgentEvent, profile: AgentProfile) -> Signal | None:
        if not self.matcher(event):
            return None
        evidence = _evidence(event)
        discriminator = self.id
        if self.aggregation is not None and self.timeframe_s is not None:
            group = (
                _as_text(event.field(self.aggregation.group_by))
                if self.aggregation.group_by
                else ""
            )
            value = _as_text(event.field(self.aggregation.field)) if self.aggregation.field else ""
            window = f"sigma:{self.id}:{group}"
            profile.window_add(window, event.timestamp, value, span_s=self.timeframe_s)
            entries = profile.windows.get(window, [])
            measured = len({v for _, v in entries}) if self.aggregation.field else len(entries)
            if not self.aggregation.holds(measured):
                return None
            evidence["aggregate_count"] = measured
            evidence["timeframe_s"] = self.timeframe_s
            discriminator = f"{self.id}:{group}"
        return Signal(
            detector="sigma",
            rule_id=self.id,
            title=self.title,
            description=self.description,
            severity=self.level,
            score=LEVEL_SCORE[self.level],
            discriminator=discriminator,
            techniques=self.techniques,
            evidence=evidence,
            event_id=event.event_id,
            agent_id=event.agent_id,
            observed_at=event.timestamp,
        )


def _scoped(kind: EventKind, base: Matcher) -> Matcher:
    return lambda e: e.kind is kind and base(e)


def _evidence(event: AgentEvent) -> dict[str, Any]:
    keys = ("kind", "action", "tool", "resource", "outcome", "destination", "delegate")
    out: dict[str, Any] = {k: _as_text(event.field(k))[:256] for k in keys if event.field(k)}
    if event.bytes_out:
        out["bytes_out"] = event.bytes_out
    out["classification"] = int(event.classification)
    return out


class RuleSet:
    def __init__(self, rules: Iterable[SigmaRule], *, digest: str) -> None:
        self.rules = tuple(rules)
        ids = [r.id for r in self.rules]
        duplicates = sorted({i for i in ids if ids.count(i) > 1})
        if duplicates:
            raise RuleValidationError(f"duplicate rule ids: {duplicates}")
        self.digest = digest

    @classmethod
    def from_directory(cls, directory: Path) -> RuleSet:
        files = sorted([*directory.glob("*.yml"), *directory.glob("*.yaml")])
        if not files:
            raise RuleValidationError(f"no detection rules found in {directory}")
        hasher = hashlib.sha256()
        rules: list[SigmaRule] = []
        for path in files:
            text = path.read_text(encoding="utf-8")
            hasher.update(path.name.encode() + b"\0" + text.encode())
            for document in yaml.safe_load_all(text):
                if document:
                    rules.append(SigmaRule.parse(document, source=path.name))
        return cls(rules, digest="sha256:" + hasher.hexdigest())

    def evaluate(self, event: AgentEvent, profile: AgentProfile) -> list[Signal]:
        signals: list[Signal] = []
        for rule in self.rules:
            signal = rule.evaluate(event, profile)
            if signal is not None:
                signals.append(signal)
        return signals
