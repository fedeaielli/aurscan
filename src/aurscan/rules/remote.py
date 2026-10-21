"""R07: network access inside build functions."""

from __future__ import annotations

from aurscan.models import Finding, Severity
from aurscan.rules import RuleContext, register
from aurscan.rules.common import (
    BUILD_FUNCTIONS,
    NETWORK_CMDS,
    finding,
    is_package_function,
    iter_pkgbuild_commands,
    network_label,
)


@register("R07", Severity.MEDIUM)
def r07_network_in_build(ctx: RuleContext) -> list[Finding]:
    """Flag network commands in ``prepare``/``build``/``package``.

    Split-package variants (``package_foo``) are included. ``check`` is not
    flagged: running a test suite that talks to the network is common.
    """
    findings: list[Finding] = []
    for function, command in iter_pkgbuild_commands(ctx.pkgbuild):
        if function not in BUILD_FUNCTIONS and not is_package_function(function):
            continue
        if command.name not in NETWORK_CMDS:
            continue
        findings.append(
            finding(
                "R07",
                Severity.MEDIUM,
                f"{network_label(command.name)} runs inside {function}()",
                "PKGBUILD",
                line=command.line,
                snippet=command.raw,
            )
        )
    return findings
