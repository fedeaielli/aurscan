"""Per-rule tests for R15."""

from __future__ import annotations

from aurscan.models import Severity
from tests.rules_utils import by_rule, run_rules

PKGBUILD = """\
pkgname=demo
pkgver=1.0
pkgrel=1
arch=('x86_64')
install=demo.install
"""


def test_r15_flags_missing_install_script() -> None:
    findings = by_rule(run_rules(PKGBUILD, cloned_files=("PKGBUILD",)), "R15")

    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert "missing.install" not in findings[0].message
    assert "demo.install" in findings[0].message


def test_r15_accepts_present_install_script() -> None:
    findings = run_rules(PKGBUILD, cloned_files=("PKGBUILD", "demo.install"))
    assert by_rule(findings, "R15") == []


def test_r15_stays_silent_without_a_file_list() -> None:
    assert by_rule(run_rules(PKGBUILD), "R15") == []


def test_r15_stays_silent_without_install_declaration() -> None:
    source = PKGBUILD.replace("install=demo.install\n", "")
    assert by_rule(run_rules(source, cloned_files=("PKGBUILD",)), "R15") == []
