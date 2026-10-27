"""R07, R18: network access and disabled TLS verification in build functions."""

from __future__ import annotations

from aurscan.constants import PKGBUILD_FILENAME
from aurscan.models import Command, Finding, Severity
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
                PKGBUILD_FILENAME,
                line=command.line,
                snippet=command.raw,
            )
        )
    return findings


@register("R18", Severity.MEDIUM)
def r18_disabled_tls_verification(ctx: RuleContext) -> list[Finding]:
    """Flag ``curl``/``wget`` invocations that disable TLS certificate verification.

    ``curl`` disables verification with ``--insecure`` or its ``-k`` short flag,
    including combined short-option clusters such as ``-fsSLk``. ``wget`` uses
    ``--no-check-certificate``; its ``-k`` means ``--convert-links`` and is not
    a TLS flag. Only ``prepare``, ``build``, ``package`` and ``package_*`` are
    inspected, matching R07, so both rules can report the same command.
    """
    findings: list[Finding] = []
    for function, command in iter_pkgbuild_commands(ctx.pkgbuild):
        if function not in BUILD_FUNCTIONS and not is_package_function(function):
            continue
        flag = _tls_disabled_flag(command)
        if flag is None:
            continue
        findings.append(
            finding(
                "R18",
                Severity.MEDIUM,
                f"{command.name} disables TLS certificate verification "
                f"with {flag} in {function}()",
                PKGBUILD_FILENAME,
                line=command.line,
                snippet=command.raw,
            )
        )
    return findings


def _tls_disabled_flag(command: Command) -> str | None:
    """Return the argument that disables TLS verification, if any."""
    for argument in command.args:
        if command.name == "curl":
            if argument == "--insecure":
                return argument
            if (
                len(argument) > 1
                and argument.startswith("-")
                and not argument.startswith("--")
                and "k" in argument[1:]
            ):
                return argument
        elif command.name == "wget" and argument == "--no-check-certificate":
            return argument
    return None
