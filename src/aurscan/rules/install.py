"""R11: risky commands inside ``.install`` hook functions."""

from __future__ import annotations

from aurscan.models import Command, Finding, Severity
from aurscan.rules import RuleContext, register
from aurscan.rules.common import (
    NETWORK_CMDS,
    decoder_kind,
    finding,
    iter_install_commands,
    network_label,
)


@register("R11", Severity.HIGH)
def r11_install_hooks(ctx: RuleContext) -> list[Finding]:
    """Flag network, base64, eval, and decoding commands in install hooks.

    Every function in an ``.install`` file is treated as a hook; commands outside
    hook functions are ignored.
    """
    findings: list[Finding] = []
    for script in ctx.install_scripts:
        for function, command in iter_install_commands(script):
            description = _risky_description(command)
            if description is None:
                continue
            findings.append(
                finding(
                    "R11",
                    Severity.HIGH,
                    f"{description} in install hook {function}()",
                    script.filename,
                    line=command.line,
                    snippet=command.raw,
                )
            )
    return findings


def _risky_description(command: Command) -> str | None:
    if command.name in NETWORK_CMDS:
        return f"{network_label(command.name)} is run"
    if command.name == "base64":
        return "base64 is run"
    if command.name in {"eval", "exec"}:
        return f"{command.name} is run"
    decoded = decoder_kind(command)
    if decoded is not None:
        return f"{decoded}-decoded content is handled"
    return None
