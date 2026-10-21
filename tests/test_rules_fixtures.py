"""Fixture sweeps: suspicious content must fire, benign content must stay quiet."""

from __future__ import annotations

from pathlib import Path

import pytest

from aurscan.models import Severity
from tests.rules_utils import run_rules

FIXTURES = Path(__file__).parent / "fixtures"
SUSPICIOUS = sorted((FIXTURES / "suspicious").iterdir())
BENIGN = [
    FIXTURES / "benign" / "PKGBUILD",
    FIXTURES / "pkgbuild" / "typical.PKGBUILD",
    FIXTURES / "install" / "basic.install",
]


@pytest.mark.parametrize("path", SUSPICIOUS, ids=lambda path: path.name)
def test_suspicious_fixture_triggers_at_least_one_finding(path: Path) -> None:
    source = path.read_text(encoding="utf-8")
    if path.suffix == ".install":
        findings = run_rules(
            install_source=source,
            install_filename=path.name,
            cloned_files=("PKGBUILD",),
        )
    else:
        findings = run_rules(source, cloned_files=("PKGBUILD",))

    assert findings, f"{path.name} did not trigger any rule"


@pytest.mark.parametrize("path", BENIGN, ids=lambda path: path.name)
def test_benign_fixture_has_no_medium_or_high_findings(path: Path) -> None:
    source = path.read_text(encoding="utf-8")
    if path.suffix == ".install":
        findings = run_rules(install_source=source, install_filename=path.name)
    else:
        findings = run_rules(source)

    noisy = [
        finding
        for finding in findings
        if finding.severity in {Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL}
    ]
    assert noisy == []
