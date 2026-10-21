"""R08: persistence outside ``$pkgdir``."""

from __future__ import annotations

from aurscan.models import Command, Finding, Severity
from aurscan.rules import RuleContext, register
from aurscan.rules.common import finding, iter_commands

_CRON_NEEDLES = ("crontab", "/etc/cron", "/var/spool/cron")
_SHELL_STARTUP_NEEDLES = (
    ".bashrc",
    ".bash_profile",
    ".zshrc",
    ".profile",
    "/etc/profile.d",
)
_AUTOSTART_NEEDLES = (".config/autostart", "/etc/xdg/autostart")


@register("R08", Severity.HIGH)
def r08_persistence(ctx: RuleContext) -> list[Finding]:
    """Flag cron, shell-startup, loader, autostart, and service persistence.

    ``systemctl enable`` is downgraded to low when it appears in a ``.install``
    script, which is the standard place to enable a package's service.
    """
    findings: list[Finding] = []
    for file, function, command in iter_commands(ctx):
        detected = _persistence_kind(command)
        if detected is None:
            continue
        description, service = detected
        severity = (
            Severity.LOW
            if service and file.endswith(".install")
            else Severity.HIGH
        )
        findings.append(
            finding(
                "R08",
                severity,
                f"{description} in {function}()",
                file,
                line=command.line,
                snippet=command.raw,
            )
        )
    return findings


def _persistence_kind(command: Command) -> tuple[str, bool] | None:
    """Return ``(description, is_service)`` for a persistence command."""
    if command.name == "systemctl" and "enable" in command.args:
        return "enables a system service", True
    raw = command.raw
    if any(needle in raw for needle in _CRON_NEEDLES):
        return "installs a cron job", False
    if any(needle in raw for needle in _SHELL_STARTUP_NEEDLES):
        return "modifies a shell startup file", False
    if "ld.so.preload" in raw:
        return "modifies the dynamic-loader preload list", False
    if any(needle in raw for needle in _AUTOSTART_NEEDLES):
        return "installs an autostart entry", False
    return None
