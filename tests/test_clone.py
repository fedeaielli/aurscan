"""Tests for the hardened git clone. Repositories are created locally."""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import types
from collections.abc import Callable
from contextlib import nullcontext
from pathlib import Path

import pytest

import aurscan.clone as clone
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


class _FakeEntry:
    """Minimal ``os.DirEntry`` stand-in for the size short-circuit test."""

    def __init__(self, path: str, size: int) -> None:
        self.path = path
        self._size = size

    def is_symlink(self) -> bool:
        return False

    def is_dir(self, *, follow_symlinks: bool = False) -> bool:
        return False

    def is_file(self, *, follow_symlinks: bool = False) -> bool:
        return True

    def stat(self, *, follow_symlinks: bool = False) -> types.SimpleNamespace:
        return types.SimpleNamespace(st_size=self._size)


def test_directory_size_short_circuits_after_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    entries = [_FakeEntry("first", 2048), _FakeEntry("second", 2048)]

    def fake_scandir(_path: object) -> object:
        return nullcontext(iter(entries))

    monkeypatch.setattr(clone.os, "scandir", fake_scandir)

    # Only the first file is counted: traversal must stop once max_bytes is exceeded.
    assert clone._directory_size(tmp_path, max_bytes=1024) == 2048


def test_remove_clone_logs_rmtree_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    dest = tmp_path / "clone"
    dest.mkdir()

    def failing_rmtree(
        path: object, *, onexc: Callable[..., object] | None = None
    ) -> None:
        assert onexc is not None
        onexc(os.unlink, str(path), PermissionError("denied"))

    monkeypatch.setattr(shutil, "rmtree", failing_rmtree)

    with caplog.at_level(logging.WARNING, logger="aurscan.clone"):
        clone._remove_clone(dest)

    assert "could not remove" in caplog.text
    assert "denied" in caplog.text
