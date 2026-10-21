"""R12: obfuscated or high-entropy payloads.

The thresholds are intentionally conservative and documented here because the
plan leaves their exact values open:

* high entropy: longer than 200 characters, no whitespace, >= 4.5 bits/char;
* repeated escapes: a run of at least 8 consecutive ``\\xNN`` escapes;
* printf: at least 8 hex or octal escape sequences on the command's line.
"""

from __future__ import annotations

from collections.abc import Iterator

from aurscan.models import Finding, Severity
from aurscan.rules import RuleContext, register
from aurscan.rules.common import (
    PKGBUILD_FILE,
    count_printf_escapes,
    finding,
    has_hex_escape_run,
    iter_string_literals,
    shannon_entropy,
)

HIGH_ENTROPY_MIN_LENGTH = 200
HIGH_ENTROPY_MIN_BITS = 4.5
HEX_ESCAPE_RUN_MINIMUM = 8
PRINTF_ESCAPE_MINIMUM = 8


@register("R12", Severity.MEDIUM)
def r12_obfuscation(ctx: RuleContext) -> list[Finding]:
    """Flag long high-entropy strings, escape runs, and escape-heavy printf calls."""
    findings: list[Finding] = []
    for file, raw in _sources(ctx):
        for line, reason, snippet in _problems(raw):
            findings.append(
                finding(
                    "R12",
                    Severity.MEDIUM,
                    reason,
                    file,
                    line=line,
                    snippet=snippet,
                )
            )
    return findings


def _sources(ctx: RuleContext) -> Iterator[tuple[str, str]]:
    if ctx.pkgbuild is not None:
        yield PKGBUILD_FILE, ctx.pkgbuild.raw
    for script in ctx.install_scripts:
        yield script.filename, script.raw


def _problems(raw: str) -> list[tuple[int, str, str]]:
    """Return at most one ``(line, reason, snippet)`` per source line."""
    reasons: dict[int, tuple[str, str]] = {}
    for literal, line in iter_string_literals(raw):
        if line in reasons:
            continue
        if (
            len(literal) > HIGH_ENTROPY_MIN_LENGTH
            and not any(character.isspace() for character in literal)
            and shannon_entropy(literal) >= HIGH_ENTROPY_MIN_BITS
        ):
            reasons[line] = ("contains a high-entropy string", literal)
        elif has_hex_escape_run(literal, minimum=HEX_ESCAPE_RUN_MINIMUM):
            reasons[line] = ("contains a long run of \\xNN escapes", literal)

    for number, text in enumerate(raw.splitlines(), start=1):
        if number in reasons or text.lstrip().startswith("#"):
            continue
        if "printf" in text and count_printf_escapes(text) >= PRINTF_ESCAPE_MINIMUM:
            reasons[number] = ("printf uses many escaped bytes", text)

    return [(line, reason, snippet) for line, (reason, snippet) in sorted(reasons.items())]
