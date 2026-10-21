"""Tests for name validation and terminal sanitization."""

import pytest

from aurscan.errors import InvalidPackageNameError
from aurscan.validation import sanitize_text, validate_package_name


@pytest.mark.parametrize(
    "name",
    ["demo", "foo-bin", "python-foo", "a", "pkg@1", "x" * 255, "a.b_c+d-e"],
)
def test_valid_package_names(name: str) -> None:
    assert validate_package_name(name) == name


@pytest.mark.parametrize(
    "name",
    ["", "Demo", "foo bar", "foo/bar", "foo\nbar", "x" * 256, "\x1b[31mdemo"],
)
def test_invalid_package_names(name: str) -> None:
    with pytest.raises(InvalidPackageNameError):
        validate_package_name(name)


def test_invalid_name_error_is_sanitized() -> None:
    with pytest.raises(InvalidPackageNameError) as excinfo:
        validate_package_name("\x1b[31mBad\x1b[0m")
    assert "\x1b" not in str(excinfo.value)


def test_sanitize_strips_ansi() -> None:
    assert sanitize_text("\x1b[31mred\x1b[0m") == "red"


def test_sanitize_strips_osc() -> None:
    assert sanitize_text("a\x1b]0;title\x07b") == "ab"
    assert sanitize_text("a\x1b]8;;https://example.invalid\x1b\\b") == "ab"


def test_sanitize_strips_bidi() -> None:
    assert sanitize_text("safe\u202eevil\u202c") == "safeevil"


def test_sanitize_removes_controls_and_collapses_whitespace() -> None:
    assert sanitize_text("a\n\tb\x07") == "a b"


def test_sanitize_truncates() -> None:
    assert sanitize_text("x" * 10, max_length=5) == "xxxx…"
    assert sanitize_text("x" * 10, max_length=1) == "…"
    assert len(sanitize_text("x" * 10, max_length=5)) == 5


def test_sanitize_empty() -> None:
    assert sanitize_text("") == ""


def test_sanitize_rejects_invalid_max_length() -> None:
    with pytest.raises(ValueError):
        sanitize_text("x", max_length=0)
