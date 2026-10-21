"""Rule registry and shared rule context.

Rules live in sibling modules and self-register through :func:`register` (or
:func:`register_aggregate` for rules that inspect findings produced earlier).
Importing :mod:`aurscan.rules` loads every built-in rule module.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from importlib import import_module

from aurscan.models import Finding, InstallScript, PackageInfo, Pkgbuild, Severity

RuleFunc = Callable[["RuleContext"], list[Finding]]
AggregateRuleFunc = Callable[["RuleContext", Sequence[Finding]], list[Finding]]

SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


@dataclass(frozen=True)
class RuleContext:
    """Everything a rule may inspect. Content is parsed, never executed."""

    pkgbuild: Pkgbuild | None
    install_scripts: tuple[InstallScript, ...]
    meta: PackageInfo | None
    cloned_files: tuple[str, ...] = ()
    now: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True)
class Rule:
    """A rule that maps context to findings."""

    rule_id: str
    severity: Severity
    func: RuleFunc


@dataclass(frozen=True)
class AggregateRule:
    """A rule that also sees the findings produced by normal rules."""

    rule_id: str
    severity: Severity
    func: AggregateRuleFunc


class RuleRegistry:
    """An ordered, append-only registry of rules."""

    def __init__(self) -> None:
        self._rules: dict[str, Rule | AggregateRule] = {}

    @property
    def rules(self) -> tuple[Rule | AggregateRule, ...]:
        """Return the registered rules in registration order."""
        return tuple(self._rules.values())

    def register(self, rule_id: str, severity: Severity) -> Callable[[RuleFunc], RuleFunc]:
        """Return a decorator that registers a content rule."""

        def decorator(func: RuleFunc) -> RuleFunc:
            self._add(Rule(rule_id=rule_id, severity=severity, func=func))
            return func

        return decorator

    def register_aggregate(
        self, rule_id: str, severity: Severity
    ) -> Callable[[AggregateRuleFunc], AggregateRuleFunc]:
        """Return a decorator that registers a rule consuming earlier findings."""

        def decorator(func: AggregateRuleFunc) -> AggregateRuleFunc:
            self._add(AggregateRule(rule_id=rule_id, severity=severity, func=func))
            return func

        return decorator

    def run_all(self, ctx: RuleContext) -> list[Finding]:
        """Run every registered rule and return deduplicated, sorted findings."""
        findings: list[Finding] = []
        aggregates: list[AggregateRule] = []
        for rule in self._rules.values():
            if isinstance(rule, AggregateRule):
                aggregates.append(rule)
            else:
                findings.extend(rule.func(ctx))
        for aggregate in aggregates:
            findings.extend(aggregate.func(ctx, tuple(findings)))
        return sort_findings(dedupe_findings(findings))

    def _add(self, rule: Rule | AggregateRule) -> None:
        if rule.rule_id in self._rules:
            raise ValueError(f"rule already registered: {rule.rule_id}")
        self._rules[rule.rule_id] = rule


def dedupe_findings(findings: Sequence[Finding]) -> list[Finding]:
    """Drop duplicate findings with the same ``(rule_id, file, line)`` key."""
    seen: set[tuple[str, str, int | None]] = set()
    unique: list[Finding] = []
    for finding in findings:
        key = (finding.rule_id, finding.file, finding.line)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


def sort_findings(findings: Sequence[Finding]) -> list[Finding]:
    """Return findings in report order: severity, file, line, rule id."""
    return sorted(
        findings,
        key=lambda item: (
            -SEVERITY_RANK[item.severity],
            item.file,
            item.line if item.line is not None else 0,
            item.rule_id,
        ),
    )


registry = RuleRegistry()
register = registry.register
register_aggregate = registry.register_aggregate


_RULE_MODULES = (
    "download",
    "sources",
    "remote",
    "persistence",
    "permissions",
    "install",
    "obfuscation",
    "network",
    "sensitive",
    "unanalyzed",
    "meta",
)


def _load_builtin_rules() -> None:
    """Import every built-in rule module so decorators populate the registry."""
    for module in _RULE_MODULES:
        import_module(f"aurscan.rules.{module}")


_load_builtin_rules()
