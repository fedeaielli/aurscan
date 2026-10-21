"""Weighted risk score and verdict, loaded from ``config/scoring.yml``.

Weights and thresholds are never hardcoded here. The default lookup prefers the
source-tree configuration (development and ``uv run``) and falls back to the copy
packaged into the wheel (``uv tool install``).
"""

from __future__ import annotations

from collections.abc import Sequence
from functools import lru_cache
from importlib.resources import files
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from aurscan.errors import ConfigError
from aurscan.models import Finding, Severity, Verdict

CONFIG_RELATIVE_PATH = Path("config") / "scoring.yml"
PACKAGED_CONFIG_RESOURCE = ("aurscan.config", "scoring.yml")


class ScoringThresholds(BaseModel):
    """Score boundaries between verdicts."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    review: int = Field(ge=0)
    risky: int = Field(ge=0)


class ScoringConfig(BaseModel):
    """Validated contents of ``config/scoring.yml``."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    max_score: int = Field(gt=0)
    weights: dict[Severity, int]
    thresholds: ScoringThresholds

    @model_validator(mode="after")
    def _validate_values(self) -> ScoringConfig:
        missing = set(Severity) - set(self.weights)
        unknown = set(self.weights) - set(Severity)
        if missing or unknown:
            raise ValueError(
                "weights must define exactly the known severities; "
                f"missing={sorted(item.value for item in missing)}, "
                f"unknown={sorted(item.value for item in unknown)}"
            )
        if any(weight < 0 for weight in self.weights.values()):
            raise ValueError("weights must not be negative")
        if self.thresholds.review >= self.thresholds.risky:
            raise ValueError("review threshold must be lower than the risky threshold")
        if self.thresholds.risky > self.max_score:
            raise ValueError("risky threshold must not exceed max_score")
        return self


def load_scoring_config(path: Path | None = None) -> ScoringConfig:
    """Return the scoring configuration, optionally from an explicit ``path``."""
    if path is not None:
        return _parse_config(_read_path(path), origin=str(path))
    return _default_config()


def score(
    findings: Sequence[Finding],
    *,
    config: ScoringConfig | None = None,
) -> tuple[int, Verdict]:
    """Return the capped weighted score and its verdict for ``findings``."""
    active = config or load_scoring_config()
    total = sum(active.weights[finding.severity] for finding in findings)
    capped = max(0, min(total, active.max_score))
    return capped, verdict_for(capped, config=active)


def verdict_for(total: int, *, config: ScoringConfig | None = None) -> Verdict:
    """Map a numeric score to a verdict using the configured thresholds."""
    active = config or load_scoring_config()
    if total >= active.thresholds.risky:
        return Verdict.RISKY
    if total >= active.thresholds.review:
        return Verdict.REVIEW
    return Verdict.OK


@lru_cache(maxsize=1)
def _default_config() -> ScoringConfig:
    source_tree = _read_source_tree_config()
    if source_tree is not None:
        return _parse_config(source_tree, origin=str(_source_tree_path()))
    packaged = _read_packaged_config()
    if packaged is not None:
        return _parse_config(packaged, origin="packaged aurscan/config/scoring.yml")
    raise ConfigError("scoring configuration not found: config/scoring.yml is missing")


def _source_tree_path() -> Path:
    return Path(__file__).resolve().parents[2] / CONFIG_RELATIVE_PATH


def _read_source_tree_config() -> str | None:
    root = Path(__file__).resolve().parents[2]
    candidate = root / CONFIG_RELATIVE_PATH
    if candidate.is_file() and (root / "pyproject.toml").is_file():
        return _read_path(candidate)
    return None


def _read_packaged_config() -> str | None:
    package, name = PACKAGED_CONFIG_RESOURCE
    resource = files(package).joinpath(name)
    if not resource.is_file():
        return None
    return resource.read_text(encoding="utf-8")


def _read_path(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read scoring configuration: {path}") from exc


def _parse_config(text: str, *, origin: str) -> ScoringConfig:
    try:
        data: Any = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in scoring configuration at {origin}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"scoring configuration at {origin} must be a mapping")
    try:
        return ScoringConfig.model_validate(data)
    except ValidationError as exc:
        raise ConfigError(f"invalid scoring configuration at {origin}: {exc}") from exc
