"""Snapshot tests for severity colors and the human score bar."""

from __future__ import annotations

from rich.console import Console

from aurscan.models import Finding, Report, Severity, Verdict
from aurscan.report import render_human
from aurscan.scoring import load_scoring_config
from tests.rules_utils import make_meta

EXPECTED_SEVERITY_COLORS: dict[Severity, str] = {
    Severity.HIGH: "\x1b[31m",
    Severity.MEDIUM: "\x1b[33m",
    Severity.LOW: "\x1b[36m",
    Severity.INFO: "\x1b[2m",
}


def _finding(rule_id: str, severity: Severity) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        message=f"example {severity.value} finding",
        file="PKGBUILD",
        line=1,
        snippet=None,
        source="static",
    )


def _colored_report() -> Report:
    findings = [
        _finding("R01", Severity.HIGH),
        _finding("R04", Severity.MEDIUM),
        _finding("R06", Severity.LOW),
        _finding("PARSE-001", Severity.INFO),
    ]
    return Report(
        package=make_meta(),
        findings=findings,
        score=40,
        verdict=Verdict.REVIEW,
        errors=[],
        dependencies=[],
        dep_of=None,
    )


def test_severity_colors_snapshot() -> None:
    console = Console(
        record=True,
        force_terminal=True,
        color_system="standard",
        width=200,
    )

    render_human(_colored_report(), console, config=load_scoring_config())
    output = console.export_text(styles=True)

    for severity, color in EXPECTED_SEVERITY_COLORS.items():
        expected = f"{color}[{severity.value.upper()}]"
        assert expected in output


def test_score_bar_snapshot() -> None:
    console = Console(
        record=True,
        force_terminal=True,
        color_system="standard",
        width=200,
    )

    render_human(_colored_report(), console, config=load_scoring_config())
    output = console.export_text()

    expected_bar = "\u2588" * 8 + "\u2591" * 12
    assert f"Risk: REVIEW (40/100) {expected_bar}" in output
