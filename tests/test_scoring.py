"""Tests for configuration-driven scoring."""

from __future__ import annotations

from pathlib import Path

import pytest

from aurscan.errors import ConfigError
from aurscan.models import Finding, Severity, Verdict
from aurscan.scoring import (
    CONFIG_RELATIVE_PATH,
    load_scoring_config,
    score,
    verdict_for,
)

REPO_ROOT = Path(__file__).parents[1]


def _finding(severity: Severity) -> Finding:
    return Finding(
        rule_id="TEST",
        severity=severity,
        message="test finding",
        file="PKGBUILD",
        line=None,
        snippet=None,
        source="static",
    )


def test_default_config_is_the_repository_config() -> None:
    assert load_scoring_config() == load_scoring_config(REPO_ROOT / CONFIG_RELATIVE_PATH)


def test_no_findings_score_zero_and_ok() -> None:
    assert score([]) == (0, Verdict.OK)


def test_each_severity_uses_the_configured_weight() -> None:
    config = load_scoring_config()
    for severity in Severity:
        total, _verdict = score([_finding(severity)], config=config)
        assert total == config.weights[severity]


def test_score_is_capped_at_max_score() -> None:
    config = load_scoring_config()
    weight = config.weights[Severity.HIGH]
    assert weight > 0
    findings = [_finding(Severity.HIGH) for _ in range(config.max_score // weight + 1)]

    total, verdict = score(findings, config=config)

    assert total == config.max_score
    assert verdict == verdict_for(config.max_score, config=config)


def test_verdict_boundaries_follow_the_config() -> None:
    config = load_scoring_config()
    review = config.thresholds.review
    risky = config.thresholds.risky

    assert verdict_for(review - 1, config=config) == Verdict.OK
    assert verdict_for(review, config=config) == Verdict.REVIEW
    assert verdict_for(risky - 1, config=config) == Verdict.REVIEW
    assert verdict_for(risky, config=config) == Verdict.RISKY


def test_explicit_path_is_loaded(tmp_path: Path) -> None:
    path = tmp_path / "scoring.yml"
    path.write_text(
        "max_score: 10\n"
        "weights:\n"
        "  info: 0\n"
        "  low: 1\n"
        "  medium: 2\n"
        "  high: 3\n"
        "  critical: 4\n"
        "thresholds:\n"
        "  review: 2\n"
        "  risky: 5\n",
        encoding="utf-8",
    )

    config = load_scoring_config(path)

    assert config.max_score == 10
    assert score([_finding(Severity.HIGH)], config=config) == (3, Verdict.REVIEW)


def test_missing_file_raises_config_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="cannot read"):
        load_scoring_config(tmp_path / "missing.yml")


def test_invalid_config_raises_config_error(tmp_path: Path) -> None:
    path = tmp_path / "scoring.yml"
    path.write_text("max_score: 10\nweights: {}\nthresholds: {review: 2, risky: 5}\n")

    with pytest.raises(ConfigError, match="invalid scoring configuration"):
        load_scoring_config(path)
