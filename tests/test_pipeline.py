"""End-to-end clone-to-parse tests using local throwaway git repositories."""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

import pytest

import aurscan.deps as deps
import aurscan.pipeline as pipeline
from aurscan.clone import clone_package
from aurscan.errors import CloneResourceError, InvalidPackageNameError
from aurscan.models import ParseResult
from aurscan.pipeline import parse_package, parse_package_with_history
from tests.rules_utils import make_meta


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
    assert "PKGBUILD" in result.cloned_files
    assert "demo.install" in result.cloned_files
    assert "extra.install" in result.cloned_files
    assert not any(path.startswith(".git/") for path in result.cloned_files)


def test_parse_package_expands_pkgname_in_install_filename(tmp_path: Path) -> None:
    source = """\
pkgname=google-chrome
pkgver=1.0
pkgrel=1
arch=('x86_64')
install=$pkgname.install
"""
    repo = _make_repo(
        tmp_path / "source",
        {"PKGBUILD": source, "google-chrome.install": INSTALL},
    )

    result = parse_package("google-chrome", _git_url=repo.as_uri())

    assert result.errors == []
    assert [script.filename for script in result.install_scripts] == [
        "google-chrome.install"
    ]


def test_parse_package_reports_missing_install_file(tmp_path: Path) -> None:
    source = PKGBUILD.replace("install=demo.install", "install=missing.install")
    repo = _make_repo(tmp_path / "source", {"PKGBUILD": source})

    result = parse_package("demo", _git_url=repo.as_uri())

    assert result.pkgbuild is not None
    assert result.parse_failed is False
    assert result.install_scripts == []
    assert result.cloned_files == ["PKGBUILD"]
    assert len(result.errors) == 1
    assert "missing.install" in result.errors[0]


def test_parse_package_surfaces_clone_failure_without_raising(tmp_path: Path) -> None:
    result = parse_package("demo", _git_url=(tmp_path / "missing").as_uri())

    assert result.pkgbuild is None
    assert result.install_scripts == []
    assert result.parse_failed is True
    assert len(result.errors) == 1
    assert "Could not clone repo for demo" in result.errors[0]
    assert "analysis based on metadata only" in result.errors[0]


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


@pytest.fixture
def clone_depths(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """Record the depth of every clone_package call made by the pipeline."""
    depths: list[int] = []
    real_clone = clone_package

    def recording(*args: object, **kwargs: object) -> Path:
        depths.append(int(kwargs["depth"]))  # type: ignore[arg-type]
        return real_clone(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(pipeline, "clone_package", recording)
    return depths


def test_parse_package_with_history_uses_a_single_clone(
    tmp_path: Path, clone_depths: list[int]
) -> None:
    repo = _make_repo(tmp_path / "source", {"PKGBUILD": PKGBUILD})
    _git(repo, "commit", "--allow-empty", "-m", "second")

    result, commits = parse_package_with_history(
        "demo", _git_url=repo.as_uri(), history_commits=2
    )

    assert clone_depths == [3]
    assert result.parse_failed is False
    assert result.pkgbuild is not None
    assert [commit.message for commit in commits] == ["second", "initial"]


def test_parse_package_with_history_clone_failure_is_metadata_only(
    tmp_path: Path, clone_depths: list[int]
) -> None:
    result, commits = parse_package_with_history(
        "demo", _git_url=(tmp_path / "missing").as_uri()
    )

    assert clone_depths == [11]
    assert commits == []
    assert result.parse_failed is True
    assert "Could not clone repo for demo" in result.errors[0]


def test_parse_package_with_history_empty_repository_notes_history_failure(
    tmp_path: Path, clone_depths: list[int]
) -> None:
    repo = tmp_path / "empty"
    repo.mkdir()
    _git(repo, "init", "-b", "main")

    result, commits = parse_package_with_history("demo", _git_url=repo.as_uri())

    assert clone_depths == [11]
    assert commits == []
    assert result.parse_failed is True
    assert any(
        error.startswith("history analysis failed:") for error in result.errors
    )


def test_parse_package_without_history_clones_depth_one(
    tmp_path: Path, clone_depths: list[int]
) -> None:
    repo = _make_repo(tmp_path / "source", {"PKGBUILD": PKGBUILD})

    result = parse_package("demo", _git_url=repo.as_uri())

    assert clone_depths == [1]
    assert result.parse_failed is False


def test_parse_package_with_history_retries_at_depth_one_on_size_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _make_repo(tmp_path / "source", {"PKGBUILD": PKGBUILD})
    depths: list[int] = []
    real_clone = clone_package

    def fake_clone(
        name: str, dest: Path, *, depth: int = 1, **_kwargs: object
    ) -> Path:
        depths.append(depth)
        if depth == 11:
            raise CloneResourceError("cloned repository exceeds 52428800 bytes")
        return real_clone(name, dest, url=repo.as_uri(), depth=depth)

    monkeypatch.setattr(pipeline, "clone_package", fake_clone)

    result, commits = parse_package_with_history("demo", _git_url=repo.as_uri())

    assert depths == [11, 1]
    assert result.parse_failed is False
    assert commits == []
    assert any(
        error.startswith("history skipped:") and "exceeds" in error
        for error in result.errors
    )


def test_parse_package_with_history_does_not_retry_generic_clone_errors(
    tmp_path: Path, clone_depths: list[int]
) -> None:
    result, commits = parse_package_with_history(
        "demo", _git_url=(tmp_path / "missing").as_uri()
    )

    assert clone_depths == [11]
    assert commits == []
    assert result.parse_failed is True
    assert not any("history skipped" in error for error in result.errors)


def test_parse_package_with_history_retry_failure_is_metadata_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    depths: list[int] = []
    real_clone = clone_package

    def fake_clone(
        name: str, dest: Path, *, depth: int = 1, **_kwargs: object
    ) -> Path:
        depths.append(depth)
        if depth == 11:
            raise CloneResourceError("cloned repository exceeds 52428800 bytes")
        return real_clone(
            name, dest, url=(tmp_path / "missing").as_uri(), depth=depth
        )

    monkeypatch.setattr(pipeline, "clone_package", fake_clone)

    result, commits = parse_package_with_history(
        "demo", _git_url=(tmp_path / "missing").as_uri()
    )

    assert depths == [11, 1]
    assert result.parse_failed is True
    assert commits == []
    assert result.errors[0].startswith("Could not clone repo for demo")


def test_parse_package_with_history_cleans_temporary_directory_on_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sandbox = tmp_path / "tmp"
    sandbox.mkdir()
    monkeypatch.setenv("TMPDIR", str(sandbox))
    monkeypatch.setattr(tempfile, "tempdir", None)

    parse_package_with_history("demo", _git_url=(tmp_path / "missing").as_uri())
    assert list(sandbox.iterdir()) == []

    repo = _make_repo(tmp_path / "source", {"PKGBUILD": PKGBUILD})
    real_clone = clone_package
    depths: list[int] = []

    def fake_clone(
        name: str, dest: Path, *, depth: int = 1, **_kwargs: object
    ) -> Path:
        depths.append(depth)
        if depth == 11:
            raise CloneResourceError("cloned repository exceeds 52428800 bytes")
        return real_clone(name, dest, url=repo.as_uri(), depth=depth)

    monkeypatch.setattr(pipeline, "clone_package", fake_clone)
    parse_package_with_history("demo", _git_url=repo.as_uri())

    assert depths == [11, 1]
    assert list(sandbox.iterdir()) == []


def test_dependency_analysis_uses_a_single_content_only_clone(
    tmp_path: Path, clone_depths: list[int], monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _make_repo(
        tmp_path / "dep", {"PKGBUILD": PKGBUILD, "demo.install": INSTALL}
    )
    real_parse = pipeline.parse_package

    def fake_parse(
        name: str, *, timeout: float = 30.0, _git_url: str | None = None
    ) -> ParseResult:
        return real_parse(name, timeout=timeout, _git_url=repo.as_uri())

    monkeypatch.setattr(deps, "parse_package", fake_parse)

    report = deps.analyze_package(make_meta(name="demo"), timeout=5.0)

    assert clone_depths == [1]
    assert report.package.name == "demo"
    assert report.errors == []
