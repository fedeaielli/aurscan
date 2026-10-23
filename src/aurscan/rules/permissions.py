"""R09-R10, R17: setuid/setgid bits and writes outside ``$pkgdir``."""

from __future__ import annotations

import re

from aurscan.models import Command, Finding, Severity
from aurscan.rules import RuleContext, register
from aurscan.rules.common import (
    BUILD_FUNCTIONS,
    finding,
    is_absolute_target,
    is_device_target,
    is_package_function,
    is_under_pkgdir,
    iter_commands,
    iter_pkgbuild_commands,
    write_destinations,
)

_OCTAL_DIGITS_RE = re.compile(r"^[0-7]+$")
_MODE_TARGETS = "ugoa"
_MODE_PERMISSIONS = "rwxXst"
# Short options of ``install`` that consume a value, so a flag bundle can be
# walked left to right without mistaking an option value for a flag.
_INSTALL_ARG_SHORTS = frozenset({"S", "Z", "g", "m", "o", "t"})


@register("R09", Severity.HIGH)
def r09_privilege_bits(ctx: RuleContext) -> list[Finding]:
    """Flag ``chmod`` calls that set the setuid or setgid bit.

    Setuid is high. Setgid-only is low, matching the plan's allowance for
    group-shared helpers. Modes that remove the bit (``u-s``) or clear it with
    ``=`` are ignored, and a bare ``chown root`` is not flagged on its own.
    """
    findings: list[Finding] = []
    for file, function, command in iter_commands(ctx):
        if command.name != "chmod":
            continue
        setuid, setgid = _mode_bits(command)
        if not setuid and not setgid:
            continue
        severity = Severity.HIGH if setuid else Severity.LOW
        description = "sets the setuid bit" if setuid else "sets the setgid bit"
        findings.append(
            finding(
                "R09",
                severity,
                f"chmod {description} in {function}()",
                file,
                line=command.line,
                snippet=command.raw,
            )
        )
    return findings


@register("R10", Severity.MEDIUM)
def r10_write_outside_pkgdir(ctx: RuleContext) -> list[Finding]:
    """Flag absolute write destinations in ``package()`` outside ``$pkgdir``.

    Relative destinations and device targets are ignored in M3; this keeps the
    rule conservative until architecture/source tracking is expanded in M6.
    """
    findings: list[Finding] = []
    for function, command in iter_pkgbuild_commands(ctx.pkgbuild):
        if not is_package_function(function):
            continue
        for destination in write_destinations(command):
            if not is_absolute_target(destination):
                continue
            if is_under_pkgdir(destination) or is_device_target(destination):
                continue
            findings.append(
                finding(
                    "R10",
                    Severity.MEDIUM,
                    f"writes outside $pkgdir: {destination}",
                    "PKGBUILD",
                    line=command.line,
                    snippet=command.raw,
                )
            )
            break
    return findings


@register("R17", Severity.HIGH)
def r17_install_privilege_bits(ctx: RuleContext) -> list[Finding]:
    """Flag ``install -m`` modes that set the setuid or setgid bit.

    This is the install-command counterpart of :func:`r09_privilege_bits`:
    ``install -m 4755`` never ran ``chmod``, so R09 cannot see it. Setuid is
    high and setgid-only is low, matching R09. Only ``prepare``, ``build``,
    ``package`` and ``package_*`` are inspected; plain modes such as ``0755``
    and bit-removing modes such as ``u-s`` are ignored. A mode held in a
    variable, or carried by a flag bundle without an inline value, is not
    resolved and therefore never reported.
    """
    findings: list[Finding] = []
    for function, command in iter_pkgbuild_commands(ctx.pkgbuild):
        if function not in BUILD_FUNCTIONS and not is_package_function(function):
            continue
        if command.name != "install":
            continue
        bits = [_bits_of(mode) for mode in _install_modes(command)]
        setuid = any(user_bit for user_bit, _group_bit in bits)
        setgid = any(group_bit for _user_bit, group_bit in bits)
        if not setuid and not setgid:
            continue
        severity = Severity.HIGH if setuid else Severity.LOW
        description = "sets the setuid bit" if setuid else "sets the setgid bit"
        findings.append(
            finding(
                "R17",
                severity,
                f"install -m {description} in {function}()",
                "PKGBUILD",
                line=command.line,
                snippet=command.raw,
            )
        )
    return findings


def _mode_bits(command: Command) -> tuple[bool, bool]:
    """Return ``(setuid, setgid)`` for the mode argument of a chmod command.

    Only the first non-option argument is a mode; everything after it is a path
    and must never be parsed symbolically (``/usr/...`` contains an ``s``).
    """
    mode = next(
        (argument for argument in command.args if not argument.startswith("-")), None
    )
    return _bits_of(mode) if mode else (False, False)


def _bits_of(mode: str) -> tuple[bool, bool]:
    """Return ``(setuid, setgid)`` for a chmod or install mode string."""
    return _octal_bits(mode) if _OCTAL_DIGITS_RE.match(mode) else _symbolic_mode_bits(mode)


def _octal_bits(mode: str) -> tuple[bool, bool]:
    """Return the special bits of an octal mode, ignoring leading zeros.

    Fewer than four significant digits (``755``, ``0644``) cannot carry the
    setuid or setgid bit, so they are never flagged.
    """
    digits = mode.lstrip("0")
    if len(digits) < 4:
        return False, False
    first = int(digits[0], 8)
    return bool(first & 4), bool(first & 2)


def _install_modes(command: Command) -> list[str]:
    """Return the ``-m``/``--mode`` values of an ``install`` command line."""
    modes: list[str] = []
    args = command.args
    for index, argument in enumerate(args):
        value = ""
        if argument in {"-m", "--mode"}:
            value = args[index + 1] if index + 1 < len(args) else ""
        elif argument.startswith("--mode="):
            value = argument.partition("=")[2]
        elif argument.startswith("-") and not argument.startswith("--"):
            value = _bundled_mode(argument) or ""
        if value:
            modes.append(value)
    return modes


def _bundled_mode(flags: str) -> str | None:
    """Return the mode carried inline by a short-flag bundle such as ``-Dm755``."""
    for position, flag in enumerate(flags[1:], start=1):
        if flag not in _INSTALL_ARG_SHORTS:
            continue
        if flag != "m":
            return None
        return flags[position + 1 :] or None
    return None


def _symbolic_mode_bits(mode: str) -> tuple[bool, bool]:
    """Apply symbolic mode clauses in order and return the final bit state.

    ``chmod u-s`` removes a bit and must not be reported. ``+`` and ``=`` set the
    bit only when the permission list contains ``s``; ``=`` without ``s`` clears
    it. The ``o`` target does not affect the setuid or setgid bits.
    """
    setuid = False
    setgid = False
    for clause in mode.split(","):
        target, operations = _parse_clause(clause)
        users = target or "a"
        affects_uid = "u" in users or "a" in users
        affects_gid = "g" in users or "a" in users
        for operator, permissions in operations:
            if operator == "=":
                if affects_uid:
                    setuid = "s" in permissions
                if affects_gid:
                    setgid = "s" in permissions
            elif "s" in permissions:
                if affects_uid:
                    setuid = operator == "+"
                if affects_gid:
                    setgid = operator == "+"
    return setuid, setgid


def _parse_clause(clause: str) -> tuple[str, list[tuple[str, str]]]:
    """Split one symbolic clause into target letters and ordered operations."""
    clause = clause.strip()
    target = clause[: len(clause) - len(clause.lstrip(_MODE_TARGETS))]
    operations: list[tuple[str, str]] = []
    rest = clause[len(target) :]
    while rest and rest[0] in "+-=":
        operator = rest[0]
        rest = rest[1:]
        permissions = rest[: len(rest) - len(rest.lstrip(_MODE_PERMISSIONS))]
        rest = rest[len(permissions) :]
        operations.append((operator, permissions))
    return target, operations
