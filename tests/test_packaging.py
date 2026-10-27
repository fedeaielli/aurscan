"""Static checks for the package metadata and README."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from aurscan.rules import registry

ROOT = Path(__file__).resolve().parents[1]
PKGBUILD = ROOT / "PKGBUILD"
README = ROOT / "README.md"
LICENSE = ROOT / "LICENSE"
RULE_ROW_RE = re.compile(r"^\| `([A-Z]\d\d)` \| ([a-z]+) \|", re.MULTILINE)

REQUIRED_DEPENDS = (
    "python",
    "python-httpx",
    "python-typer",
    "python-rich",
    "python-pydantic",
    "python-pyyaml",
    "python-tree-sitter",
    "python-tree-sitter-bash",
    "git",
)


def test_pkgbuild_is_valid_bash() -> None:
    result = subprocess.run(
        ["bash", "-n", str(PKGBUILD)],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr


def test_pkgbuild_uses_uv_and_declares_runtime_dependencies() -> None:
    text = PKGBUILD.read_text(encoding="utf-8")

    assert "makedepends=('uv')" in text
    assert "source=()" in text
    assert "uv build --wheel" in text
    assert '"$pkgdir' in text
    for dependency in REQUIRED_DEPENDS:
        assert f"'{dependency}'" in text


def test_license_is_declared_and_present() -> None:
    pkgbuild = PKGBUILD.read_text(encoding="utf-8")
    license_text = LICENSE.read_text(encoding="utf-8")

    assert "license=('GPL-3.0-or-later')" in pkgbuild
    assert "Copyright (C) 2026 faielli" in license_text
    assert "GNU GENERAL PUBLIC LICENSE" in license_text
    assert "Version 3, 29 June 2007" in license_text


def test_readme_documents_install_usage_limits_and_rules() -> None:
    text = README.read_text(encoding="utf-8")

    for heading in (
        "## Installation",
        "## Usage",
        "## Known limits",
        "## Contributing rules",
        "## License",
    ):
        assert heading in text

    assert "pacman -S uv" in text
    assert "uv tool install aurscan" in text
    assert "aurscan --explain R01" in text
    assert "aurscan --rules" in text
    assert "GPL-3.0-or-later" in text


def test_readme_rule_table_matches_registered_rules() -> None:
    documented: dict[str, str] = {}
    for rule_id, severity in RULE_ROW_RE.findall(README.read_text(encoding="utf-8")):
        assert rule_id not in documented, f"duplicate README row for {rule_id}"
        documented[rule_id] = severity

    expected = {rule.rule_id: rule.severity.value for rule in registry.rules}
    m01 = registry.explain("M01")
    assert m01 is not None
    expected["M01"] = m01[0].value

    missing_in_readme = sorted(set(expected) - set(documented))
    missing_in_registry = sorted(set(documented) - set(expected))
    drifted = sorted(
        rule
        for rule in documented.keys() & expected
        if documented[rule] != expected[rule]
    )
    assert documented == expected, (
        f"README-only: {missing_in_registry}; "
        f"registry-only: {missing_in_readme}; "
        f"severity drift: {drifted}"
    )
