"""Word splitting, variable expansion and path helpers. Nothing here executes a shell."""

from __future__ import annotations

import re
import shlex
from pathlib import PurePosixPath

_VARIABLE_RE = re.compile(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))")
_MAX_EXPANSIONS = 5


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


def expand_variables(text: str, variables: dict[str, str | list[str]]) -> str:
    """Substitute simple ``$var``/``${var}`` references from parsed assignments.

    Only top-level string assignments are expanded; array values and unknown
    names are left untouched. Expansion is bounded so self-references cannot loop.
    """
    expanded = text
    for _ in range(_MAX_EXPANSIONS):
        updated = _expand_once(expanded, variables)
        if updated == expanded:
            break
        expanded = updated
    return expanded


def _expand_once(text: str, variables: dict[str, str | list[str]]) -> str:
    def _replace(match: re.Match[str]) -> str:
        name = match.group(1) or match.group(2)
        value = variables.get(name)
        return value if isinstance(value, str) else match.group(0)

    return _VARIABLE_RE.sub(_replace, text)
