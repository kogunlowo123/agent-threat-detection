"""Sigma-style rule parsing, matching and aggregation."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
import yaml

from agent_threat_detection.detection.baseline import AgentProfile
from agent_threat_detection.detection.sigma import (
    RuleSet,
    SigmaRule,
    _wildcards,
    parse_timeframe,
)
from agent_threat_detection.domain.errors import RuleValidationError
from agent_threat_detection.domain.events import AgentEvent, EventKind, Outcome
from agent_threat_detection.domain.findings import Severity
from tests.conftest import ROOT, START, agent_uri, event


def rule(detection: dict[str, Any], **extra: Any) -> SigmaRule:
    doc: dict[str, Any] = {
        "title": "test rule",
        "id": "test-rule",
        "level": "high",
        "logsource": {"product": "agent"},
        "detection": detection,
    }
    doc.update(extra)
    return SigmaRule.parse(doc)


def profile() -> AgentProfile:
    return AgentProfile.new(agent_uri(), at=START, order=3)


def matches(r: SigmaRule, e: AgentEvent) -> bool:
    return r.evaluate(e, profile()) is not None


def test_repository_rules_load_and_carry_attack_mappings() -> None:
    rules = RuleSet.from_directory(ROOT / "rules")
    assert len(rules.rules) >= 9
    assert rules.digest.startswith("sha256:")
    by_id = {r.id: r for r in rules.rules}
    tamper = by_id["atd-audit-tampering"]
    assert tamper.level is Severity.CRITICAL
    assert [t.uid for t in tamper.techniques] == ["T1562"]
    shell = by_id["atd-execution-shell-tool"]
    assert {t.uid for t in shell.techniques} == {"T1059", "AML.T0053"}


@pytest.mark.parametrize(
    ("spec", "value", "candidate", "expected"),
    [
        ("action|contains", "StopLogging", "cloudtrail:stoplogging", True),
        ("action|startswith", "iam:", "IAM:attach", True),
        ("action|endswith", ":delete", "s3:delete", True),
        ("action|re", "^iam[:.]", "iam.create", True),
        ("action|re", "^iam[:.]", "xiam.create", False),
        ("action", "crm.*", "crm.lookup", True),
        ("action", "crm.?ookup", "crm.lookup", True),
        ("action", r"literal\*", "literal*", True),
        ("action", r"literal\*", "literalX", False),
        ("action", r"back\\slash", "back\\slash", True),
        ("action", "Exact", "exact", True),
        ("action|cased", "Exact", "exact", False),
        ("action|contains|cased", "Stop", "stoplogging", False),
        ("action", "[bracket", "[bracket", True),
        ("bytes_out|gt", 10, 11, True),
        ("bytes_out|gte", 10, 10, True),
        ("bytes_out|lt", 10, 10, False),
        ("bytes_out|lte", 10, 10, True),
        ("bytes_out", 7, 7, True),
        ("bytes_out", 7, 8, False),
    ],
)
def test_field_modifiers(spec: str, value: Any, candidate: Any, expected: bool) -> None:
    field = spec.split("|", maxsplit=1)[0]
    e = event(**{field: candidate}) if field != "action" else event(action=candidate)
    assert matches(rule({"sel": {spec: value}, "condition": "sel"}), e) is expected


def test_values_lists_all_exists_none_bool_and_attributes() -> None:
    any_of = rule({"sel": {"action|contains": ["x", "query"]}, "condition": "sel"})
    assert matches(any_of, event(action="ledger.query"))
    all_of = rule({"sel": {"action|contains|all": ["ledger", "query"]}, "condition": "sel"})
    assert matches(all_of, event(action="ledger.query"))
    assert not matches(all_of, event(action="ledger.read"))
    exists = rule({"sel": {"destination|exists": True}, "condition": "sel"})
    assert matches(exists, event(destination="a.corp.internal"))
    assert not matches(exists, event())
    missing = rule({"sel": {"destination": None}, "condition": "sel"})
    assert matches(missing, event())
    flag = rule({"sel": {"attributes.approved_runtime": True}, "condition": "sel"})
    assert matches(flag, event(attributes={"approved_runtime": True}))
    assert not matches(flag, event(attributes={"approved_runtime": 1}))
    scopes = rule({"sel": {"scopes_requested": [r"\*"]}, "condition": "sel"})
    assert matches(scopes, event(EventKind.TOKEN, scopes_requested=("*", "crm:read")))
    assert not matches(scopes, event(EventKind.TOKEN, scopes_requested=("crm:read",)))
    assert not matches(scopes, event(EventKind.TOKEN))
    numeric = rule({"sel": {"classification|gte": 3}, "condition": "sel"})
    assert not matches(numeric, event(attributes={}, classification=2))
    typed = rule({"sel": {"attributes.n|gt": 1}, "condition": "sel"})
    assert not matches(typed, event(attributes={"n": "five"}))
    alternatives = rule({"sel": [{"action": "a"}, {"tool": "b"}], "condition": "sel"})
    assert matches(alternatives, event(action="x", tool="b"))


def test_conditions() -> None:
    detection = {
        "sel_a": {"action": "a"},
        "sel_b": {"tool": "b"},
        "filter": {"outcome": "denied"},
    }
    cases = {
        "sel_a and not filter": (event(action="a"), True),
        "(sel_a or sel_b) and filter": (event(action="a", outcome=Outcome.DENIED), True),
        "1 of sel_*": (event(action="x", tool="b"), True),
        "all of sel_*": (event(action="a", tool="b"), True),
        "any of them": (event(action="zzz", outcome=Outcome.DENIED), True),
        "all of them": (event(action="a", tool="b"), False),
        "not not sel_a": (event(action="a"), True),
    }
    for condition, (e, expected) in cases.items():
        assert matches(rule({**detection, "condition": condition}), e) is expected, condition


def test_category_scopes_rule_to_event_kind() -> None:
    r = rule(
        {"sel": {"action": "a"}, "condition": "sel"},
        logsource={"product": "agent", "category": "data_transfer"},
    )
    assert not matches(r, event(action="a"))
    assert matches(r, event(EventKind.DATA_TRANSFER, action="a"))


def test_count_aggregation_with_timeframe() -> None:
    r = rule(
        {
            "sel": {"kind": "tool_call"},
            "timeframe": "1m",
            "condition": "sel | count() by agent_id > 2",
        }
    )
    p = profile()
    results = [r.evaluate(event(at=START + timedelta(seconds=i)), p) for i in range(4)]
    assert [x is not None for x in results] == [False, False, True, True]
    later = r.evaluate(event(at=START + timedelta(minutes=5)), p)
    assert later is None
    assert results[2] is not None
    assert results[2].evidence["aggregate_count"] == 3


def test_distinct_count_aggregation() -> None:
    r = rule(
        {"sel": {"destination|exists": True}, "condition": "sel | count(destination) >= 2"},
        timeframe="5m",
    )
    p = profile()
    first = r.evaluate(event(EventKind.DATA_TRANSFER, destination="a.test"), p)
    same = r.evaluate(event(EventKind.DATA_TRANSFER, destination="a.test"), p)
    other = r.evaluate(event(EventKind.DATA_TRANSFER, destination="b.test"), p)
    assert first is None
    assert same is None
    assert other is not None
    for op, value, expected in (("<", 5, True), ("<", 1, False), ("==", 1, True), ("<=", 0, False)):
        q = rule(
            {
                "sel": {"kind": "tool_call"},
                "timeframe": "1h",
                "condition": f"sel | count() {op} {value}",
            }
        )
        assert (q.evaluate(event(), profile()) is not None) is expected


@pytest.mark.parametrize(
    ("document", "message"),
    [
        (
            {"id": "Bad Id", "title": "t", "detection": {"sel": {"action": 1}, "condition": "sel"}},
            "slug",
        ),
        ({"logsource": {"product": "windows"}}, "product"),
        ({"logsource": {"product": "agent", "category": "nope"}}, "category"),
        ({"detection": {"sel": {"action": "a"}}}, "condition is required"),
        ({"level": "urgent"}, "invalid level"),
        ({"detection": {"condition": "sel"}}, "no selections"),
        ({"detection": {"sel": {"action": "a"}, "condition": 3}}, "must be a string"),
        ({"detection": {"sel": {"nofield": "a"}, "condition": "sel"}}, "unknown field"),
        ({"detection": {"sel": {"action|base64": "a"}, "condition": "sel"}}, "unknown modifiers"),
        ({"detection": {"sel": {"action|gt|lt": 1}, "condition": "sel"}}, "conflicting"),
        ({"detection": {"sel": {"action|gt": "x"}, "condition": "sel"}}, "needs a number"),
        ({"detection": {"sel": {"action|re": "("}, "condition": "sel"}}, "invalid regular"),
        ({"detection": {"sel": {"action|re": "a" * 600}, "condition": "sel"}}, "512"),
        ({"detection": {"sel": {"action|exists": "yes"}, "condition": "sel"}}, "true or false"),
        ({"detection": {"sel": {"action": []}, "condition": "sel"}}, "empty value list"),
        ({"detection": {"sel": {"action": {"a": 1}}, "condition": "sel"}}, "unsupported value"),
        ({"detection": {"sel": {}, "condition": "sel"}}, "is empty"),
        ({"detection": {"sel": "keyword", "condition": "sel"}}, "mapping"),
        ({"detection": {"sel": {"action": "a"}, "condition": "sel and"}}, "expected"),
        ({"detection": {"sel": {"action": "a"}, "condition": "other"}}, "unknown selection"),
        ({"detection": {"sel": {"action": "a"}, "condition": "1 of zz*"}}, "no selection"),
        ({"detection": {"sel": {"action": "a"}, "condition": "sel sel"}}, "unexpected token"),
        ({"detection": {"sel": {"action": "a"}, "condition": "sel $"}}, "cannot parse"),
        ({"detection": {"sel": {"action": "a"}, "condition": "sel | sum() > 1"}}, "only count"),
        (
            {
                "detection": {
                    "sel": {"action": "a"},
                    "condition": "sel | count(zz) > 1",
                    "timeframe": "1m",
                }
            },
            "aggregation field",
        ),
        (
            {
                "detection": {
                    "sel": {"action": "a"},
                    "condition": "sel | count() by zz > 1",
                    "timeframe": "1m",
                }
            },
            "group-by",
        ),
        (
            {
                "detection": {
                    "sel": {"action": "a"},
                    "condition": "sel | count() ( 1",
                    "timeframe": "1m",
                }
            },
            "operator",
        ),
        (
            {
                "detection": {
                    "sel": {"action": "a"},
                    "condition": "sel | count() > x",
                    "timeframe": "1m",
                }
            },
            "integer",
        ),
        ({"detection": {"sel": {"action": "a"}, "condition": "sel | count() > 1"}}, "timeframe"),
        (
            {"detection": {"sel": {"action": "a"}, "condition": "sel", "timeframe": "soon"}},
            "timeframe",
        ),
    ],
)
def test_invalid_rules_are_rejected(document: dict[str, Any], message: str) -> None:
    base: dict[str, Any] = {
        "title": "t",
        "id": "valid-id",
        "logsource": {"product": "agent"},
        "detection": {"sel": {"action": "a"}, "condition": "sel"},
    }
    with pytest.raises(RuleValidationError, match=message):
        SigmaRule.parse({**base, **document})


def test_missing_required_keys() -> None:
    with pytest.raises(RuleValidationError, match="missing required key"):
        SigmaRule.parse({"logsource": {"product": "agent"}, "detection": {"condition": "x"}})


def test_rule_set_files_and_duplicates(tmp_path: Path) -> None:
    with pytest.raises(RuleValidationError, match="no detection rules"):
        RuleSet.from_directory(tmp_path)
    doc = {
        "title": "t",
        "id": "dup-rule",
        "logsource": {"product": "agent"},
        "detection": {"sel": {"action": "a"}, "condition": "sel"},
    }
    (tmp_path / "a.yml").write_text(yaml.safe_dump(doc) + "---\n", encoding="utf-8")
    (tmp_path / "b.yaml").write_text(yaml.safe_dump(doc), encoding="utf-8")
    with pytest.raises(RuleValidationError, match="duplicate"):
        RuleSet.from_directory(tmp_path)


def test_helpers() -> None:
    assert parse_timeframe("30s") == 30
    assert parse_timeframe("2h") == 7200
    assert parse_timeframe("1d") == 86400
    assert _wildcards(r"a\*b*") == ("a*b", "a[*]b*")
    assert _wildcards("plain") == ("plain", None)
    tags = rule(
        {"sel": {"action": "a"}, "condition": "sel"},
        tags=["attack.t9999", "cve.2024", "atlas.aml.t0051"],
    )
    assert [t.uid for t in tags.techniques] == ["AML.T0051"]
