"""R15: declared install script missing from the clone."""

from __future__ import annotations

import re
from pathlib import PurePosixPath

from aurscan.models import Finding, Severity
from aurscan.rules import RuleContext, register
from aurscan.rules.common import finding, line_of

_VARIABLE_RE = re.compile(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))")
_MAX_EXPANSIONS = 5


@register("R15", Severity.MEDIUM)
def r15_missing_install_script(ctx: RuleContext) -> list[Finding]:
    """Flag an ``install=`` declaration whose file is absent from the clone.

    An empty file list means the clone could not be enumerated; the rule stays
    silent then instead of reporting a false positive.
    """
    pkgbuild = ctx.pkgbuild
    if pkgbuild is None or not pkgbuild.install or not ctx.cloned_files:
        return []
    declared = PurePosixPath(
        _expand_variables(pkgbuild.install, pkgbuild.variables)
    ).as_posix()
    if declared in set(ctx.cloned_files):
        return []
    return [
        finding(
            "R15",
            Severity.MEDIUM,
            f"install script declared but not found in the clone: {pkgbuild.install}",
            "PKGBUILD",
            line=line_of(pkgbuild.raw, "install="),
            snippet=pkgbuild.install,
        )
    ]


def _expand_variables(text: str, variables: dict[str, str | list[str]]) -> str:
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
