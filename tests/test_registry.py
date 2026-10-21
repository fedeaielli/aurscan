"""Tests for the rule registry: registration, ordering, deduplication."""

from __future__ import annotations

import pytest

from aurscan.models import Finding, Severity
from aurscan.rules import RuleContext, RuleRegistry, registry
from aurscan.rules.common import finding
from tests.rules_utils import parse_source

ALL_RULE_IDS = {
    "R01",
    "R02",
    "R03",
    "R04",
    "R05",
    "R06",
    "R07",
    "R08",
    "R09",
    "R10",
    "R11",
    "R12",
    "R13",
    "R14",
    "R15",
    "M01",
    "M02",
    "M03",
    "M04",
}


def _context() -> RuleContext:
    return RuleContext(pkgbuild=parse_source(""), install_scripts=(), meta=None)


def test_builtin_rules_are_registered() -> None:
    assert {rule.rule_id for rule in registry.rules} == ALL_RULE_IDS


def test_findings_are_deduplicated_and_sorted() -> None:
    rules = RuleRegistry()

    @rules.register("X01", Severity.LOW)
    def _rule(_ctx: RuleContext) -> list[Finding]:
        return [
            finding("X01", Severity.LOW, "second", "PKGBUILD", line=2),
            finding("X01", Severity.LOW, "first", "PKGBUILD", line=1),
            finding("X01", Severity.LOW, "duplicate", "PKGBUILD", line=1),
        ]

    findings = rules.run_all(_context())

    assert [item.message for item in findings] == ["first", "second"]


def test_aggregate_rules_run_after_normal_rules() -> None:
    rules = RuleRegistry()

    @rules.register_aggregate("A02", Severity.LOW)
    def _aggregate(_ctx: RuleContext, findings: object) -> list[Finding]:
        assert isinstance(findings, tuple)
        return [finding("A02", Severity.LOW, f"seen {len(findings)}", "PKGBUILD")]

    @rules.register("A01", Severity.HIGH)
    def _normal(_ctx: RuleContext) -> list[Finding]:
        return [finding("A01", Severity.HIGH, "high", "PKGBUILD")]

    findings = rules.run_all(_context())

    assert [item.rule_id for item in findings] == ["A01", "A02"]
    assert findings[1].message == "seen 1"


def test_duplicate_registration_is_rejected() -> None:
    rules = RuleRegistry()
    rules.register("X01", Severity.LOW)(lambda _ctx: [])

    with pytest.raises(ValueError, match="already registered"):
        rules.register("X01", Severity.LOW)(lambda _ctx: [])
