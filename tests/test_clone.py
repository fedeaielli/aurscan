"""Tests for the hardened git clone. Repositories are created locally."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from aurscan.clone import clone_package
from aurscan.errors import CloneError


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )


def _init_repo(repo: Path) -> None:
    repo.mkdir()
    _git(repo, "init", "-b", "main")
    _git(repo, "config", "user.name", "Test")
    _git(repo, "config", "user.email", "test@example.invalid")


def _commit(repo: Path, message: str) -> None:
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", message)


def _make_repo(repo: Path, *, commits: int = 1) -> Path:
    _init_repo(repo)
    (repo / "PKGBUILD").write_text("pkgname=demo\npkgver=1.0\n", encoding="utf-8")
    _commit(repo, "initial")
    for index in range(1, commits):
        (repo / "file.txt").write_text(f"change {index}\n", encoding="utf-8")
        _commit(repo, f"change {index}")
    return repo


def test_clone_package_clones_local_repo(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path / "source")
    dest = tmp_path / "clone"

    result = clone_package("demo", dest, url=repo.as_uri())

    assert result == dest
    assert (dest / "PKGBUILD").read_text(encoding="utf-8").startswith("pkgname=demo")


def test_clone_is_shallow(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path / "source", commits=3)
    dest = tmp_path / "clone"

    clone_package("demo", dest, url=repo.as_uri())

    count = _git(dest, "rev-list", "--count", "HEAD").stdout.strip()
    assert count == "1"


def test_clone_refuses_existing_destination(tmp_path: Path) -> None:
    dest = tmp_path / "clone"
    dest.mkdir()
    with pytest.raises(CloneError, match="already exists"):
        clone_package("demo", dest, url=(tmp_path / "missing").as_uri())


def test_clone_failure_raises_and_cleans_up(tmp_path: Path) -> None:
    dest = tmp_path / "clone"
    with pytest.raises(CloneError, match="git clone failed"):
        clone_package("demo", dest, url=(tmp_path / "missing").as_uri())
    assert not dest.exists()


def test_clone_enforces_size_limit(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path / "source")
    (repo / "big.bin").write_bytes(b"x" * 4096)
    _commit(repo, "big file")
    dest = tmp_path / "clone"

    with pytest.raises(CloneError, match="exceeds"):
        clone_package("demo", dest, url=repo.as_uri(), max_bytes=1024)
    assert not dest.exists()


def test_clone_accepts_install_script(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path / "source")
    (repo / "demo.install").write_text("post_install() { :; }\n", encoding="utf-8")
    _commit(repo, "install script")
    dest = tmp_path / "clone"

    clone_package("demo", dest, url=repo.as_uri())

    assert (dest / "demo.install").read_text(encoding="utf-8") == "post_install() { :; }\n"
