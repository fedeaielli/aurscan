"""R15: declared install script missing from the clone."""

from __future__ import annotations

from pathlib import PurePosixPath

from aurscan.models import Finding, Severity
from aurscan.rules import RuleContext, register
from aurscan.rules.common import finding, line_of


@register("R15", Severity.MEDIUM)
def r15_missing_install_script(ctx: RuleContext) -> list[Finding]:
    """Flag an ``install=`` declaration whose file is absent from the clone.

    An empty file list means the clone could not be enumerated; the rule stays
    silent then instead of reporting a false positive.
    """
    pkgbuild = ctx.pkgbuild
    if pkgbuild is None or not pkgbuild.install or not ctx.cloned_files:
        return []
    declared = PurePosixPath(pkgbuild.install).as_posix()
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
