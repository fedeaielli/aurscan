"""R01-R03: downloads piped to shells, decoding pipes, and dynamic eval."""

from __future__ import annotations

from aurscan.models import Finding, Severity
from aurscan.rules import RuleContext, register
from aurscan.rules.common import (
    commands_by_file,
    contains_substitution,
    decoder_kind,
    finding,
    iter_commands,
    pipe_runs_shell,
    runs_process_substitution_script,
)


@register("R01", Severity.HIGH)
def r01_download_to_shell(ctx: RuleContext) -> list[Finding]:
    """Flag curl/wget output executed by a shell.

    The pipe relationship comes from ``Command.in_pipe_to``. One wrapper level
    (``sudo``, ``env``, ``xargs``, ...) is looked through so ``curl | sudo bash``
    is still caught.
    """
    findings: list[Finding] = []
    grouped = commands_by_file(ctx)
    for file, function, command in iter_commands(ctx):
        if command.name in {"curl", "wget"} and pipe_runs_shell(command, grouped[file]):
            findings.append(
                finding(
                    "R01",
                    Severity.HIGH,
                    f"{command.name} output is piped to a shell in {function}()",
                    file,
                    line=command.line,
                    snippet=command.raw,
                )
            )
        elif runs_process_substitution_script(command):
            findings.append(
                finding(
                    "R01",
                    Severity.HIGH,
                    f"a shell is fed a downloaded script in {function}()",
                    file,
                    line=command.line,
                    snippet=command.raw,
                )
            )
    return findings


@register("R02", Severity.HIGH)
def r02_decode_pipe(ctx: RuleContext) -> list[Finding]:
    """Flag encoded content decoded with base64/xxd/openssl and then executed."""
    findings: list[Finding] = []
    grouped = commands_by_file(ctx)
    for file, function, command in iter_commands(ctx):
        kind = decoder_kind(command)
        if kind is None:
            continue
        target = command.in_pipe_to
        executed = pipe_runs_shell(command, grouped[file]) or target == "eval"
        if executed:
            findings.append(
                finding(
                    "R02",
                    Severity.HIGH,
                    f"{kind}-decoded content is executed in {function}()",
                    file,
                    line=command.line,
                    snippet=command.raw,
                )
            )
    return findings


@register("R03", Severity.MEDIUM)
def r03_dynamic_eval(ctx: RuleContext) -> list[Finding]:
    """Flag ``eval``/``exec`` whose argument comes from a variable or substitution."""
    findings: list[Finding] = []
    for file, function, command in iter_commands(ctx):
        if command.name not in {"eval", "exec"}:
            continue
        text = " ".join(command.args)
        if not contains_substitution(text):
            continue
        findings.append(
            finding(
                "R03",
                Severity.MEDIUM,
                f"{command.name} evaluates dynamic content in {function}()",
                file,
                line=command.line,
                snippet=command.raw,
            )
        )
    return findings
