"""Word splitting and path helpers. Nothing here executes a shell."""

from __future__ import annotations

import shlex
from pathlib import PurePosixPath


def split_words(text: str) -> list[str]:
    """Split ``text`` into shell-like words without executing anything.

    Quoting and backslashes are honoured, but variables are never expanded.
    Unbalanced quotes fall back to whitespace splitting so callers never crash.
    """
    try:
        return shlex.split(text, comments=False, posix=True)
    except ValueError:
        return text.split()


def basename(path: str) -> str:
    """Return the last component of a POSIX path."""
    stripped = path.strip()
    if not stripped:
        return ""
    return PurePosixPath(stripped).name
