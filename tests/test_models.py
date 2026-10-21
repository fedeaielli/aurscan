"""Tests for the shared pydantic models."""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from aurscan.models import (
    Finding,
    PackageInfo,
    ParseResult,
    Report,
    Severity,
    Verdict,
)

from .conftest import BASE_EPOCH

FAKE_URL = "https://example.invalid/demo"


def test_package_info_normalizes_to_utc() -> None:
    info = PackageInfo(
        name="demo",
        version="1.0-1",
        maintainer=None,
        submitter=None,
        first_submitted=datetime.fromtimestamp(BASE_EPOCH, tz=UTC),
        last_modified=datetime.fromtimestamp(BASE_EPOCH, tz=UTC),
        num_votes=0,
        popularity=0.0,
        out_of_date=None,
        url=FAKE_URL,
        depends=[],
        make_depends=[],
        opt_depends=[],
    )
    assert info.first_submitted.utcoffset() is not None
    assert info.first_submitted.utcoffset().total_seconds() == 0


def test_models_forbid_extra_fields() -> None:
    with pytest.raises(ValidationError):
        Finding(
            rule_id="R01",
            severity=Severity.HIGH,
            message="test",
            file="PKGBUILD",
            line=1,
            snippet=None,
            source="static",
            extra="nope",  # type: ignore[call-arg]
        )


def test_naive_datetime_rejected() -> None:
    with pytest.raises(ValidationError):
        PackageInfo(
            name="demo",
            version="1.0-1",
            maintainer=None,
            submitter=None,
            first_submitted=datetime(2024, 1, 1),
            last_modified=datetime(2024, 1, 1, tzinfo=UTC),
            num_votes=0,
            popularity=0.0,
            out_of_date=None,
            url=None,
            depends=[],
            make_depends=[],
            opt_depends=[],
        )


def test_parse_result_findings_default_empty() -> None:
    result = ParseResult(pkgbuild=None, install_scripts=[], parse_failed=False)
    assert result.findings == []


def test_report_supports_nested_dependencies() -> None:
    info = PackageInfo(
        name="demo",
        version="1.0-1",
        maintainer=None,
        submitter=None,
        first_submitted=datetime.fromtimestamp(BASE_EPOCH, tz=UTC),
        last_modified=datetime.fromtimestamp(BASE_EPOCH, tz=UTC),
        num_votes=0,
        popularity=0.0,
        out_of_date=None,
        url=None,
        depends=[],
        make_depends=[],
        opt_depends=[],
    )
    finding = Finding(
        rule_id="R01",
        severity=Severity.HIGH,
        message="pipes a download to a shell",
        file="PKGBUILD",
        line=3,
        snippet=None,
        source="static",
    )
    report = Report(
        package=info,
        findings=[finding],
        score=20,
        verdict=Verdict.REVIEW,
        errors=[],
        dependencies=[],
        dep_of=None,
    )
    assert report.dependencies == []
    assert Report.model_validate(report.model_dump()) == report
    serialized = report.model_dump(mode="json")
    assert serialized["package"]["first_submitted"].startswith("2023-11-14T22:13:20")
