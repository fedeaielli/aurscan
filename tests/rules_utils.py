"""Small builders shared by the per-rule tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from aurscan.models import Finding, InstallScript, PackageInfo, Pkgbuild
from aurscan.parse import parse_install_script, parse_pkgbuild
from aurscan.rules import RuleContext, registry

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def parse_source(source: str) -> Pkgbuild:
    result = parse_pkgbuild(source)
    assert result.pkgbuild is not None
    return result.pkgbuild


def parse_install(source: str, filename: str = "test.install") -> InstallScript:
    result = parse_install_script(source, filename)
    assert result.install_scripts
    return result.install_scripts[0]


def make_meta(**overrides: Any) -> PackageInfo:
    data: dict[str, Any] = {
        "name": "demo",
        "version": "1.0-1",
        "maintainer": "maintainer",
        "submitter": "submitter",
        "first_submitted": NOW - timedelta(days=365),
        "last_modified": NOW - timedelta(days=1),
        "num_votes": 42,
        "popularity": 1.5,
        "out_of_date": None,
        "url": "https://example.invalid/demo",
        "depends": [],
        "make_depends": [],
        "opt_depends": [],
    }
    data.update(overrides)
    return PackageInfo.model_validate(data)


def run_rules(
    source: str = "",
    *,
    install_source: str | None = None,
    install_filename: str = "test.install",
    meta: PackageInfo | None = None,
    cloned_files: tuple[str, ...] = (),
    now: datetime = NOW,
) -> list[Finding]:
    scripts: tuple[InstallScript, ...] = ()
    if install_source is not None:
        scripts = (parse_install(install_source, install_filename),)
    context = RuleContext(
        pkgbuild=parse_source(source),
        install_scripts=scripts,
        meta=meta,
        cloned_files=cloned_files,
        now=now,
    )
    return registry.run_all(context)


def by_rule(findings: list[Finding], rule_id: str) -> list[Finding]:
    return [finding for finding in findings if finding.rule_id == rule_id]


def rule_ids(findings: list[Finding]) -> set[str]:
    return {finding.rule_id for finding in findings}
