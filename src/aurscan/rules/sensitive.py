"""R14: access to credentials, browser profiles, and crypto wallets."""

from __future__ import annotations

from aurscan.models import Finding, Severity
from aurscan.rules import RuleContext, register
from aurscan.rules.common import SENSITIVE_PATH_NEEDLES, finding, iter_commands


@register("R14", Severity.HIGH)
def r14_sensitive_paths(ctx: RuleContext) -> list[Finding]:
    """Flag commands that mention SSH/GPG/AWS keys, browser profiles, or wallets.

    Matching is a deliberately simple substring check on the parsed command, so
    variables are never expanded and no file is touched.
    """
    findings: list[Finding] = []
    for file, function, command in iter_commands(ctx):
        for needle, description in SENSITIVE_PATH_NEEDLES:
            if needle not in command.raw:
                continue
            findings.append(
                finding(
                    "R14",
                    Severity.HIGH,
                    f"accesses {description} ({needle}) in {function}()",
                    file,
                    line=command.line,
                    snippet=command.raw,
                )
            )
            break
    return findings
