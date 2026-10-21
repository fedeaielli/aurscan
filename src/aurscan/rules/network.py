"""R13: active network access (reverse shells and raw sockets)."""

from __future__ import annotations

import re
from collections.abc import Sequence

from aurscan.models import Command, Finding, Severity
from aurscan.rules import RuleContext, register
from aurscan.rules.common import finding, function_groups, iter_commands

_NC_CMDS = frozenset({"nc", "ncat", "netcat"})
_INTERACTIVE_BASH_RE = re.compile(r"\bbash\s+-i\s+>&")


@register("R13", Severity.HIGH)
def r13_active_network(ctx: RuleContext) -> list[Finding]:
    """Flag raw-socket shells, netcat command execution, and FIFO/netcat pairs."""
    findings: list[Finding] = []
    for file, function, command in iter_commands(ctx):
        reason = _active_reason(command)
        if reason is not None:
            findings.append(
                finding(
                    "R13",
                    Severity.HIGH,
                    f"{reason} in {function}()",
                    file,
                    line=command.line,
                    snippet=command.raw,
                )
            )

    for file, function, commands in function_groups(ctx):
        if not _has_fifo_netcat(commands):
            continue
        fifo = next(command for command in commands if command.name == "mkfifo")
        findings.append(
            finding(
                "R13",
                Severity.HIGH,
                f"connects a FIFO to netcat in {function}()",
                file,
                line=fifo.line,
                snippet=fifo.raw,
            )
        )
    return findings


def _active_reason(command: Command) -> str | None:
    if "/dev/tcp/" in command.raw:
        return "uses a raw /dev/tcp socket"
    if command.name in _NC_CMDS and any(
        argument in {"-e", "--exec"} for argument in command.args
    ):
        return "runs a netcat command shell"
    if _INTERACTIVE_BASH_RE.search(command.raw):
        return "opens an interactive bash shell to a socket"
    return None


def _has_fifo_netcat(commands: Sequence[Command]) -> bool:
    has_fifo = any(command.name == "mkfifo" for command in commands)
    has_netcat = any(command.name in _NC_CMDS for command in commands)
    return has_fifo and has_netcat
