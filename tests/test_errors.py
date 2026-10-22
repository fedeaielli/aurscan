"""Tests for the error hierarchy and exit codes."""

import pytest

from aurscan.errors import (
    AurscanError,
    BinaryFileError,
    CloneError,
    ExitCode,
    FetchError,
    FileTooLargeError,
    InvalidPackageNameError,
    SafetyError,
    UnsafePathError,
)


def test_exit_code_values() -> None:
    assert ExitCode.OK == 0
    assert ExitCode.REVIEW == 1
    assert ExitCode.RISKY == 2
    assert ExitCode.ERROR == 3


@pytest.mark.parametrize(
    "error_class",
    [
        InvalidPackageNameError,
        FetchError,
        CloneError,
        SafetyError,
        UnsafePathError,
        BinaryFileError,
        FileTooLargeError,
    ],
)
def test_errors_are_operational(error_class: type[AurscanError]) -> None:
    error = error_class("boom")
    assert isinstance(error, AurscanError)
    assert error.exit_code == ExitCode.ERROR
    assert str(error) == "boom"
