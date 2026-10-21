"""Shared pydantic v2 models. All models forbid unknown fields."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Verdict(StrEnum):
    OK = "ok"
    REVIEW = "review"
    RISKY = "risky"


class AurscanModel(BaseModel):
    """Base model with strict field handling."""

    model_config = ConfigDict(extra="forbid")


class PackageInfo(AurscanModel):
    name: str
    version: str
    maintainer: str | None
    submitter: str | None
    first_submitted: AwareDatetime
    last_modified: AwareDatetime
    num_votes: int
    popularity: float
    out_of_date: AwareDatetime | None
    url: str | None
    depends: list[str]
    make_depends: list[str]
    opt_depends: list[str]

    @field_validator("first_submitted", "last_modified", "out_of_date")
    @classmethod
    def _normalize_utc(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        return value.astimezone(UTC)


class Command(AurscanModel):
    name: str
    args: list[str]
    raw: str
    in_pipe_to: str | None = None
    line: int


class Function(AurscanModel):
    name: str
    commands: list[Command]
    raw: str


class Pkgbuild(AurscanModel):
    pkgname: list[str]
    pkgver: str | None
    pkgrel: str | None
    epoch: str | None
    pkgdesc: str | None
    url: str | None
    install: str | None
    arch: list[str]
    license: list[str]
    depends: list[str]
    makedepends: list[str]
    checkdepends: list[str]
    optdepends: list[str]
    provides: list[str]
    conflicts: list[str]
    replaces: list[str]
    source: list[str]
    sha256sums: list[str]
    sha512sums: list[str]
    md5sums: list[str]
    b2sums: list[str]
    sources_by_arch: dict[str, list[str]] = Field(default_factory=dict)
    checksums_by_arch: dict[str, dict[str, list[str]]] = Field(default_factory=dict)
    functions: dict[str, list[Command]]
    variables: dict[str, str | list[str]]
    raw: str


class InstallScript(AurscanModel):
    filename: str
    functions: dict[str, list[Command]]
    commands: list[Command]
    raw: str


class ParseResult(AurscanModel):
    pkgbuild: Pkgbuild | None
    install_scripts: list[InstallScript]
    parse_failed: bool
    findings: list[Finding] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    cloned_files: list[str] = Field(default_factory=list)


class Finding(AurscanModel):
    rule_id: str
    severity: Severity
    message: str
    file: str
    line: int | None
    snippet: str | None
    source: Literal["static", "metadata", "history"]


class Report(AurscanModel):
    package: PackageInfo
    findings: list[Finding]
    score: int
    verdict: Verdict
    errors: list[str]
    dependencies: list[Report]
    dep_of: str | None


Report.model_rebuild()
