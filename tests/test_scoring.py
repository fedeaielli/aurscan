"""Tests for configuration-driven scoring."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from aurscan import scoring
from aurscan.errors import ConfigError
from aurscan.models import Finding, Severity, Verdict
from aurscan.scoring import (
    CONFIG_RELATIVE_PATH,
    load_scoring_config,
    score,
    verdict_for,
)

REPO_ROOT = Path(__file__).parents[1]

VALID_CONFIG_TEXT = (
    "max_score: 10\n"
    "weights:\n"
    "  info: 0\n"
    "  low: 1\n"
    "  medium: 2\n"
    "  high: 3\n"
    "  critical: 4\n"
    "thresholds:\n"
    "  review: 2\n"
    "  risky: 5\n"
)


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


@pytest.mark.parametrize(
    ("text", "message"),
    [
        pytest.param(
            "max_score: 10\n"
            "weights:\n"
            "  info: 0\n"
            "  low: -1\n"
            "  medium: 2\n"
            "  high: 3\n"
            "  critical: 4\n"
            "thresholds:\n"
            "  review: 2\n"
            "  risky: 5\n",
            "weights must not be negative",
            id="negative-weight",
        ),
        pytest.param(
            "max_score: 10\n"
            "weights:\n"
            "  info: 0\n"
            "  low: 1\n"
            "  medium: 2\n"
            "  high: 3\n"
            "  critical: 4\n"
            "thresholds:\n"
            "  review: 5\n"
            "  risky: 5\n",
            "review threshold must be lower than the risky threshold",
            id="review-not-below-risky",
        ),
        pytest.param(
            "max_score: 10\n"
            "weights:\n"
            "  info: 0\n"
            "  low: 1\n"
            "  medium: 2\n"
            "  high: 3\n"
            "  critical: 4\n"
            "thresholds:\n"
            "  review: 2\n"
            "  risky: 11\n",
            "risky threshold must not exceed max_score",
            id="risky-above-max-score",
        ),
    ],
)
def test_out_of_range_values_raise_config_error(
    tmp_path: Path, text: str, message: str
) -> None:
    path = tmp_path / "scoring.yml"
    path.write_text(text, encoding="utf-8")

    with pytest.raises(ConfigError, match=message):
        load_scoring_config(path)


def test_malformed_yaml_raises_config_error(tmp_path: Path) -> None:
    path = tmp_path / "scoring.yml"
    path.write_text("max_score: 10\nthresholds: [1, 2\n", encoding="utf-8")

    with pytest.raises(ConfigError, match="invalid YAML"):
        load_scoring_config(path)


def test_non_mapping_config_raises_config_error(tmp_path: Path) -> None:
    path = tmp_path / "scoring.yml"
    path.write_text("- 1\n- 2\n", encoding="utf-8")

    with pytest.raises(ConfigError, match="must be a mapping"):
        load_scoring_config(path)


@pytest.fixture(autouse=True)
def _clear_default_config_cache() -> Iterator[None]:
    """Stop the ``lru_cache``d default from leaking between tests."""
    scoring._default_config.cache_clear()
    yield
    scoring._default_config.cache_clear()


def _fake_source_tree(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the module at a source tree whose ``config/`` holds no scoring file."""
    module = tmp_path / "tree" / "src" / "aurscan" / "scoring.py"
    module.parent.mkdir(parents=True)
    monkeypatch.setattr(scoring, "__file__", str(module))
    return module.parents[2]


def _fake_package(tmp_path: Path, name: str, text: str | None) -> str:
    """Create an importable package that optionally ships a ``scoring.yml``."""
    package = tmp_path / name
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    if text is not None:
        (package / "scoring.yml").write_text(text, encoding="utf-8")
    return name


def test_source_tree_config_requires_pyproject(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _fake_source_tree(tmp_path, monkeypatch)
    config_path = root / CONFIG_RELATIVE_PATH
    config_path.parent.mkdir(parents=True)
    config_path.write_text(VALID_CONFIG_TEXT, encoding="utf-8")

    assert scoring._read_source_tree_config() is None

    (root / "pyproject.toml").write_text("[project]\nname = 'x'\n", encoding="utf-8")

    assert scoring._read_source_tree_config() == VALID_CONFIG_TEXT


def test_default_config_falls_back_to_packaged_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _fake_source_tree(tmp_path, monkeypatch)
    assert not (root / CONFIG_RELATIVE_PATH).exists()
    package = _fake_package(tmp_path, "fake_scoring_pkg", VALID_CONFIG_TEXT)
    monkeypatch.setattr(scoring, "PACKAGED_CONFIG_RESOURCE", (package, "scoring.yml"))
    monkeypatch.syspath_prepend(str(tmp_path))

    config = scoring._default_config()

    assert config.max_score == 10
    assert config.weights[Severity.HIGH] == 3
    assert config.thresholds.risky == 5


def test_default_config_missing_everywhere_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fake_source_tree(tmp_path, monkeypatch)
    package = _fake_package(tmp_path, "fake_empty_pkg", None)
    monkeypatch.setattr(scoring, "PACKAGED_CONFIG_RESOURCE", (package, "scoring.yml"))
    monkeypatch.syspath_prepend(str(tmp_path))

    with pytest.raises(ConfigError, match="scoring configuration not found"):
        scoring._default_config()
