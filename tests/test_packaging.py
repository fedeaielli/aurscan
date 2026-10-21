"""Static checks for the package metadata and README."""

from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PKGBUILD = ROOT / "PKGBUILD"
README = ROOT / "README.md"

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


def test_readme_documents_install_usage_limits_and_rules() -> None:
    text = README.read_text(encoding="utf-8")

    for heading in (
        "## Installation",
        "## Usage",
        "## Known limits",
        "## Contributing rules",
    ):
        assert heading in text

    assert "pacman -S uv" in text
    assert "uv tool install aurscan" in text
    assert "aurscan --explain R01" in text
