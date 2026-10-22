"""Shared rule helpers and constants.

Nothing here executes package content. All helpers inspect parsed commands and
raw source slices only; variables are never expanded.
"""

from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlsplit

from aurscan.models import Command, Finding, InstallScript, Pkgbuild, Severity
from aurscan.rules import RuleContext
from aurscan.shell import basename

PKGBUILD_FILE = "PKGBUILD"
METADATA_FILE = "AUR"

NETWORK_CMDS = frozenset(
    {
        "aria2c",
        "axel",
        "curl",
        "ftp",
        "git",
        "nc",
        "ncat",
        "netcat",
        "rsync",
        "scp",
        "sftp",
        "socat",
        "ssh",
        "telnet",
        "tftp",
        "wget",
    }
)

SHELL_CMDS = frozenset(
    {"ash", "bash", "busybox", "csh", "dash", "fish", "ksh", "mksh", "sh", "tcsh", "zsh"}
)

BUILD_FUNCTIONS = frozenset({"prepare", "build", "package"})

WRAPPER_CMDS = frozenset(
    {"command", "doas", "env", "exec", "nohup", "stdbuf", "sudo", "timeout", "xargs"}
)

VCS_SCHEMES = ("bzr+", "bzr://", "git+", "git://", "hg+", "hg://", "svn+", "svn://")

# Hosts that serve user-supplied content and must never be trusted as a source
# for a package, even when they happen to match the upstream project domain.
USER_CONTENT_HOSTS = frozenset(
    {
        "0x0.st",
        "anonfiles.com",
        "cdn.discordapp.com",
        "dpaste.org",
        "file.io",
        "gist.githubusercontent.com",
        "githubusercontent.com",
        "ghostbin.co",
        "hastebin.com",
        "mediafire.com",
        "mega.nz",
        "objects.githubusercontent.com",
        "paste.ee",
        "pastebin.com",
        "raw.githubusercontent.com",
        "transfer.sh",
    }
)

SENSITIVE_PATH_NEEDLES: tuple[tuple[str, str], ...] = (
    (".ssh", "SSH keys"),
    (".gnupg", "GnuPG keys"),
    (".aws", "AWS credentials"),
    (".mozilla", "browser profile"),
    (".config/google-chrome", "browser profile"),
    (".config/chromium", "browser profile"),
    (".config/BraveSoftware", "browser profile"),
    (".bitcoin", "crypto wallet"),
    (".ethereum", "crypto wallet"),
    (".electrum", "crypto wallet"),
    (".monero", "crypto wallet"),
    ("wallet.dat", "crypto wallet"),
)

_STRING_RE = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')
_REDIRECT_RE = re.compile(
    r"(?<![0-9A-Za-z_])[0-9]?>>?\|?(?![>&])\s*(\"[^\"]*\"|'[^']*'|[^\s;|&<>()]+)"
)
_HEX_ESCAPE_RUN_RE = re.compile(r"(?:\\x[0-9A-Fa-f]{2}){8,}")
_PRINTF_ESCAPE_RE = re.compile(r"\\(?:x[0-9A-Fa-f]{2}|[0-7]{1,3})")


def finding(
    rule_id: str,
    severity: Severity,
    message: str,
    file: str,
    *,
    line: int | None = None,
    snippet: str | None = None,
    source: Literal["static", "metadata", "history"] = "static",
) -> Finding:
    """Build a finding, truncating long snippets for safe terminal output."""
    return Finding(
        rule_id=rule_id,
        severity=severity,
        message=message,
        file=file,
        line=line,
        snippet=_truncate(snippet) if snippet is not None else None,
        source=source,
    )


def iter_pkgbuild_commands(pkgbuild: Pkgbuild | None) -> Iterator[tuple[str, Command]]:
    """Yield ``(function, command)`` for every command inside a PKGBUILD function."""
    if pkgbuild is None:
        return
    for function, commands in pkgbuild.functions.items():
        for command in commands:
            yield function, command


def iter_install_commands(script: InstallScript) -> Iterator[tuple[str, Command]]:
    """Yield ``(function, command)`` for install-script hook functions."""
    for function, commands in script.functions.items():
        for command in commands:
            yield function, command


def iter_commands(ctx: RuleContext) -> Iterator[tuple[str, str, Command]]:
    """Yield ``(file, function, command)`` across the PKGBUILD and install scripts."""
    for function, command in iter_pkgbuild_commands(ctx.pkgbuild):
        yield PKGBUILD_FILE, function, command
    for script in ctx.install_scripts:
        for function, command in iter_install_commands(script):
            yield script.filename, function, command


def function_groups(ctx: RuleContext) -> Iterator[tuple[str, str, list[Command]]]:
    """Yield ``(file, function, commands)`` groups for cross-command checks."""
    if ctx.pkgbuild is not None:
        for function, commands in ctx.pkgbuild.functions.items():
            yield PKGBUILD_FILE, function, commands
    for script in ctx.install_scripts:
        for function, commands in script.functions.items():
            yield script.filename, function, commands


def commands_by_file(ctx: RuleContext) -> dict[str, list[Command]]:
    """Group all commands by the file they appear in."""
    grouped: dict[str, list[Command]] = {}
    for file, _function, command in iter_commands(ctx):
        grouped.setdefault(file, []).append(command)
    return grouped


def pipe_runs_shell(command: Command, commands: Sequence[Command]) -> bool:
    """Return whether a command's stdout is piped into a shell.

    Wrappers such as ``sudo`` or ``env`` are looked through one level, matching
    the parsed ``in_pipe_to`` value instead of re-parsing the raw pipeline.
    """
    target = command.in_pipe_to
    if target is None:
        return False
    if target in SHELL_CMDS:
        return True
    if target not in WRAPPER_CMDS:
        return False
    for candidate in commands:
        if candidate.name != target or candidate.line != command.line:
            continue
        return any(basename(argument) in SHELL_CMDS for argument in candidate.args)
    return False


def runs_process_substitution_script(command: Command) -> bool:
    """Return whether a shell command is fed by ``<(curl ...)`` or ``<(wget ...)``."""
    if command.name not in SHELL_CMDS:
        return False
    return any(re.search(r"[<>]\(\s*(?:curl|wget)\b", arg) for arg in command.args)


def decoder_kind(command: Command) -> str | None:
    """Return a human label when ``command`` decodes encoded content."""
    name = command.name
    if name == "base64" and _base64_decodes(command.args):
        return "base64"
    if name == "xxd" and any(arg in {"-r", "-revert"} for arg in command.args):
        return "xxd"
    if (
        name == "openssl"
        and command.args[:1] == ["enc"]
        and any(arg in {"-d", "-decrypt"} for arg in command.args[1:])
    ):
        return "openssl"
    return None


def _base64_decodes(args: Sequence[str]) -> bool:
    return any(
        arg in {"-d", "--decode"}
        or (arg.startswith("-") and not arg.startswith("--") and "d" in arg[1:])
        for arg in args
    )


def contains_substitution(text: str) -> bool:
    """Return whether ``text`` references a variable or command substitution."""
    return "$" in text or "`" in text


def network_label(name: str) -> str:
    """Return a short human description for a network command."""
    labels = {
        "curl": "a download",
        "wget": "a download",
        "git": "a git operation",
        "ssh": "an SSH connection",
        "scp": "an SCP transfer",
        "sftp": "an SFTP transfer",
        "nc": "a netcat connection",
        "ncat": "a netcat connection",
        "netcat": "a netcat connection",
        "socat": "a socat connection",
        "rsync": "an rsync transfer",
    }
    return labels.get(name, f"a {name} network operation")


def source_url(source: str) -> str:
    """Strip the optional ``filename::`` prefix from a source entry."""
    _prefix, separator, rest = source.partition("::")
    return rest if separator else source


def is_vcs_source(source: str) -> bool:
    """Return whether a source entry points at a version-control repository."""
    return source_url(source).strip().lower().startswith(VCS_SCHEMES)


def host_of(url: str) -> str | None:
    """Return the lower-case host of an HTTP(S) URL, or ``None``."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if parts.scheme.lower() not in {"http", "https"}:
        return None
    host = parts.hostname
    return host.lower() if host else None


def url_scheme(url: str) -> str | None:
    """Return the lower-case scheme of a URL, or ``None`` when unparsable."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    return parts.scheme.lower() or None


def is_ip_host(host: str) -> bool:
    """Return whether ``host`` is a literal IPv4 or IPv6 address."""
    candidate = host.strip("[]")
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return False
    return True


def same_domain(host: str, upstream: str) -> bool:
    """Return whether ``host`` is ``upstream`` or one of its subdomains."""
    host = host.lower()
    upstream = upstream.lower()
    return host == upstream or host.endswith(f".{upstream}")


def is_user_content_host(host: str) -> bool:
    """Return whether ``host`` is a known user-content host."""
    host = host.lower()
    return any(host == known or host.endswith(f".{known}") for known in USER_CONTENT_HOSTS)


@dataclass(frozen=True)
class SourceGroup:
    """One source/checksum set: the base variables or one architecture suffix."""

    arch: str | None
    sources: list[str]
    checksums: dict[str, list[str]]

    @property
    def label(self) -> str:
        """Return the source variable name (``source`` or ``source_<arch>``)."""
        return "source" if self.arch is None else f"source_{self.arch}"

    def checksum_label(self, kind: str) -> str:
        """Return a checksum variable name for this group."""
        return kind if self.arch is None else f"{kind}_{self.arch}"


def source_groups(pkgbuild: Pkgbuild) -> tuple[SourceGroup, ...]:
    """Return the base source group followed by every architecture-specific group."""
    groups = [
        SourceGroup(
            arch=None,
            sources=pkgbuild.source,
            checksums={
                "sha256sums": pkgbuild.sha256sums,
                "sha512sums": pkgbuild.sha512sums,
                "md5sums": pkgbuild.md5sums,
                "b2sums": pkgbuild.b2sums,
            },
        )
    ]
    for arch in sorted(pkgbuild.sources_by_arch):
        groups.append(
            SourceGroup(
                arch=arch,
                sources=pkgbuild.sources_by_arch[arch],
                checksums=pkgbuild.checksums_by_arch.get(arch, {}),
            )
        )
    return tuple(groups)


def aligned_strong_checksum_in(group: SourceGroup, index: int) -> str | None:
    """Return a non-SKIP strong checksum aligned with a source group entry."""
    if index >= len(group.sources):
        return None
    for kind in ("sha256sums", "sha512sums"):
        values = group.checksums.get(kind, [])
        if len(values) != len(group.sources) or index >= len(values):
            continue
        value = values[index].strip()
        if value and value != "SKIP":
            return value
    return None


def is_package_function(name: str) -> bool:
    """Return whether ``name`` is ``package`` or a split-package variant."""
    return name == "package" or name.startswith("package_")


def redirect_targets(raw: str) -> list[str]:
    """Return the destination operands of shell output redirections."""
    return [_strip_quotes(match.group(1)) for match in _REDIRECT_RE.finditer(raw)]


def write_destinations(command: Command) -> list[str]:
    """Return paths a command writes to, or an empty list when unknown.

    Covers redirections plus common writers. Relative destinations are returned
    as-is; the caller decides whether they matter.
    """
    destinations = redirect_targets(command.raw)
    args = command.args
    name = command.name
    if name == "tee":
        return destinations + [arg for arg in args if not arg.startswith("-")]
    if name in {"cp", "mv", "install", "ln"}:
        target = _target_directory(args)
        if target is not None:
            return destinations + [target]
        operands = [arg for arg in args if not arg.startswith("-")]
        if operands:
            destinations.append(operands[-1])
        return destinations
    if name in {"mkdir", "touch"}:
        return destinations + [arg for arg in args if not arg.startswith("-")]
    if name == "sed" and any(
        arg in {"-i", "--in-place"} or arg.startswith("--in-place=") for arg in args
    ):
        operands = [arg for arg in args if not arg.startswith("-")]
        if len(operands) >= 2:
            destinations.append(operands[-1])
        return destinations
    if name == "dd":
        return destinations + [
            arg.partition("=")[2] for arg in args if arg.startswith("of=") and len(arg) > 3
        ]
    if name == "curl":
        destinations.extend(_option_value(args, "-o", "--output"))
        return destinations
    if name == "wget":
        destinations.extend(_option_value(args, "-O", "--output-document"))
        return destinations
    return destinations


def is_under_pkgdir(path: str) -> bool:
    """Return whether a destination is anchored at ``$pkgdir`` or ``$DESTDIR``."""
    clean = _strip_quotes(path)
    return clean.startswith(("$pkgdir", "${pkgdir}", "$DESTDIR", "${DESTDIR}"))


def is_absolute_target(path: str) -> bool:
    """Return whether a destination is absolute or rooted at the user's home."""
    clean = _strip_quotes(path)
    return clean.startswith(("/", "~", "$HOME", "${HOME}"))


def is_device_target(path: str) -> bool:
    """Return whether a destination is a harmless device or file descriptor."""
    clean = _strip_quotes(path)
    return clean in {"/dev/null", "/dev/stdout", "/dev/stderr"} or clean.startswith("/dev/fd/")


def iter_string_literals(text: str) -> Iterator[tuple[str, int]]:
    """Yield ``(literal, line)`` for quoted strings in raw source, skipping comments."""
    for match in _STRING_RE.finditer(text):
        line = text.count("\n", 0, match.start()) + 1
        if _line_text(text, line).lstrip().startswith("#"):
            continue
        literal = _strip_quotes(match.group(0))
        yield literal, line


def has_hex_escape_run(text: str, *, minimum: int = 8) -> bool:
    """Return whether ``text`` contains a long run of consecutive ``\\xNN`` escapes."""
    return any(len(match.group(0)) // 4 >= minimum for match in _HEX_ESCAPE_RUN_RE.finditer(text))


def count_printf_escapes(text: str) -> int:
    """Count hex and octal escape sequences in ``text``."""
    return len(_PRINTF_ESCAPE_RE.findall(text))


def shannon_entropy(text: str) -> float:
    """Return Shannon entropy in bits per character."""
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def line_of(text: str, needle: str) -> int | None:
    """Return the 1-based line containing ``needle``, or ``None``."""
    if not needle:
        return None
    index = text.find(needle)
    if index < 0:
        return None
    return text.count("\n", 0, index) + 1


def _target_directory(args: Sequence[str]) -> str | None:
    for index, arg in enumerate(args):
        if arg in {"-t", "--target-directory"} and index + 1 < len(args):
            return args[index + 1]
        if arg.startswith("--target-directory="):
            return arg.partition("=")[2]
    return None


def _option_value(args: Sequence[str], short: str, long: str) -> list[str]:
    values: list[str] = []
    for index, arg in enumerate(args):
        if arg in {short, long} and index + 1 < len(args):
            values.append(args[index + 1])
        elif arg.startswith(f"{long}="):
            values.append(arg.partition("=")[2])
    return values


def _line_text(text: str, line: int) -> str:
    lines = text.splitlines()
    if 1 <= line <= len(lines):
        return lines[line - 1]
    return ""


def _strip_quotes(text: str) -> str:
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        return text[1:-1]
    return text


def _truncate(text: str, limit: int = 200) -> str:
    if len(text) <= limit:
        return text
    return f"{text[: limit - 3]}..."
