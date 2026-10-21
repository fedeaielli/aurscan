"""End-to-end clone-to-parse tests using local throwaway git repositories."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from aurscan.errors import InvalidPackageNameError
from aurscan.pipeline import parse_package


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )


def _make_repo(repo: Path, files: dict[str, str]) -> Path:
    repo.mkdir()
    _git(repo, "init", "-b", "main")
    _git(repo, "config", "user.name", "Test")
    _git(repo, "config", "user.email", "test@example.invalid")
    for name, content in files.items():
        target = repo / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "initial")
    return repo


PKGBUILD = """\
pkgname=demo
pkgver=1.0
pkgrel=1
arch=('x86_64')
url="https://example.invalid/demo"
source=("$url/demo-$pkgver.tar.gz")
sha256sums=('SKIP')
install=demo.install

build() {
  cd "$srcdir/demo-$pkgver"
  make
}
"""

INSTALL = """\
post_install() {
  echo "installed"
}
"""


def test_parse_package_merges_pkgbuild_and_install_scripts(tmp_path: Path) -> None:
    repo = _make_repo(
        tmp_path / "source",
        {"PKGBUILD": PKGBUILD, "demo.install": INSTALL, "extra.install": INSTALL},
    )

    result = parse_package("demo", _git_url=repo.as_uri())

    assert result.errors == []
    assert result.parse_failed is False
    assert result.pkgbuild is not None
    assert result.pkgbuild.pkgname == ["demo"]
    assert result.pkgbuild.functions["build"][1].name == "make"
    assert sorted(script.filename for script in result.install_scripts) == [
        "demo.install",
        "extra.install",
    ]


def test_parse_package_reports_missing_install_file(tmp_path: Path) -> None:
    source = PKGBUILD.replace("install=demo.install", "install=missing.install")
    repo = _make_repo(tmp_path / "source", {"PKGBUILD": source})

    result = parse_package("demo", _git_url=repo.as_uri())

    assert result.pkgbuild is not None
    assert result.parse_failed is False
    assert result.install_scripts == []
    assert len(result.errors) == 1
    assert "missing.install" in result.errors[0]


def test_parse_package_surfaces_clone_failure_without_raising(tmp_path: Path) -> None:
    result = parse_package("demo", _git_url=(tmp_path / "missing").as_uri())

    assert result.pkgbuild is None
    assert result.install_scripts == []
    assert result.parse_failed is True
    assert len(result.errors) == 1
    assert "could not clone demo" in result.errors[0]


def test_parse_package_does_not_discover_nested_install_files(tmp_path: Path) -> None:
    repo = _make_repo(
        tmp_path / "source",
        {"PKGBUILD": PKGBUILD.replace("install=demo.install\n", ""), "sub/nested.install": INSTALL},
    )

    result = parse_package("demo", _git_url=repo.as_uri())

    assert result.install_scripts == []
    assert result.errors == []


def test_parse_package_rejects_invalid_names() -> None:
    with pytest.raises(InvalidPackageNameError):
        parse_package("Demo")
