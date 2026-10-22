"""Error hierarchy and process exit codes."""

from enum import IntEnum
from typing import ClassVar


class ExitCode(IntEnum):
    """Process exit codes defined by the project plan."""

    OK = 0
    REVIEW = 1
    RISKY = 2
    ERROR = 3


class AurscanError(Exception):
    """Base class for expected aurscan failures."""

    exit_code: ClassVar[ExitCode] = ExitCode.ERROR

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class InvalidPackageNameError(AurscanError):
    """The supplied package name is not a valid AUR name."""


class FetchError(AurscanError):
    """AUR metadata could not be retrieved or decoded."""


class CloneError(AurscanError):
    """The package git repository could not be cloned safely."""


class CloneResourceError(CloneError):
    """A clone failed because fetching the requested history exceeded the size
    limit or timed out.
    """


class HistoryError(AurscanError):
    """Git history could not be read safely."""


class ConfigError(AurscanError):
    """Scoring configuration is missing or invalid."""


class SafetyError(AurscanError):
    """A file-system safety invariant was violated."""


class UnsafePathError(SafetyError):
    """A path escapes its root or traverses a symlink."""


class BinaryFileError(SafetyError):
    """A file that should be text contains NUL bytes."""


class FileTooLargeError(SafetyError):
    """A file exceeds the configured size limit."""
