"""Rule registry and shared rule context.

Rules live in sibling modules and self-register through :func:`register` (or
:func:`register_aggregate` for rules that inspect findings produced earlier).
Importing :mod:`aurscan.rules` loads every built-in rule module.
"""

from __future__ import annotations

import inspect
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

    def get(self, rule_id: str) -> Rule | AggregateRule | None:
        """Return the registered rule for ``rule_id``, or ``None``."""
        return self._rules.get(rule_id)

    def explain(self, rule_id: str) -> tuple[Severity, str] | None:
        """Return the severity and full description for ``rule_id``.

        ``M01`` is implemented by the history module rather than the content
        registry, so its catalogue entry is kept here for ``--explain``.
        """
        rule = self._rules.get(rule_id)
        if rule is not None:
            return rule.severity, inspect.getdoc(rule.func) or "No description available."
        return _EXTRA_RULE_DESCRIPTIONS.get(rule_id)

    def describe(self, rule_id: str) -> str | None:
        """Return the full description for ``rule_id``, or ``None`` if unknown."""
        info = self.explain(rule_id)
        return info[1] if info is not None else None

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
    """Merge findings that share the same ``(rule_id, file, line)`` key.

    A git-history finding supersedes a static finding with the same key so the
    "new in commit" context is not lost. When the messages differ, they are
    combined into one finding instead of dropping the secondary message.
    """
    grouped: dict[tuple[str, str, int | None], list[Finding]] = {}
    for finding in findings:
        key = (finding.rule_id, finding.file, finding.line)
        grouped.setdefault(key, []).append(finding)
    return [_merge_duplicates(group) for group in grouped.values()]


def _merge_duplicates(group: Sequence[Finding]) -> Finding:
    """Return one finding per key, preferring history and keeping every message."""
    primary = next(
        (finding for finding in group if finding.source == "history"), group[0]
    )
    messages = [primary.message]
    for finding in group:
        if finding is primary:
            continue
        if any(finding.message in message for message in messages):
            continue
        messages.append(finding.message)
    if len(messages) == 1:
        return primary
    merged = primary.message + "".join(
        f" (also: {extra})" for extra in messages[1:]
    )
    return primary.model_copy(update={"message": merged})


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


_EXTRA_RULE_DESCRIPTIONS: dict[str, tuple[Severity, str]] = {
    "M01": (
        Severity.MEDIUM,
        "Flag a recent git author change on a package that is currently "
        "orphaned. AUR only exposes the current maintainer, so orphan status is "
        "the available 'previously orphaned' signal.",
    ),
}

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
