"""Git history analysis: recent commits, added-line diffs, maintainer changes.

Nothing here executes package content. Git is invoked with hooks disabled and a
sanitized environment; commit snapshots are parsed with the same static parser
used for the working tree and every finding is reported against raw text only.
"""

from __future__ import annotations

import re
import subprocess
import tempfile
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path

from pydantic import AwareDatetime, Field

from aurscan.clone import clone_package, git_env
from aurscan.errors import AurscanError, HistoryError
from aurscan.models import AurscanModel, Finding, PackageInfo, Severity
from aurscan.parse import parse_install_script, parse_pkgbuild
from aurscan.rules import RuleContext, RuleRegistry, dedupe_findings, sort_findings
from aurscan.rules.common import METADATA_FILE, finding
from aurscan.validation import sanitize_text, validate_package_name

PKGBUILD_FILENAME = "PKGBUILD"
INSTALL_SUFFIX = ".install"
SHORT_HASH_LENGTH = 7
MAX_CONTENT_BYTES = 1024 * 1024
GIT_TIMEOUT_SECONDS = 60.0

_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


class Commit(AurscanModel):
    """One commit with the data needed by the history rules.

    ``added_lines`` is keyed by path and uses 1-based line numbers in this
    commit's version of the file. ``content`` holds the complete text of the
    changed ``PKGBUILD`` / ``*.install`` files so findings can be resolved
    against the real function context instead of an isolated snippet.
    """

    hash: str
    author: str
    date: AwareDatetime
    message: str
    files: list[str] = Field(default_factory=list)
    added_lines: dict[str, list[int]] = Field(default_factory=dict)
    content: dict[str, str] = Field(default_factory=dict)
    tree_files: list[str] = Field(default_factory=list)

    @property
    def short_hash(self) -> str:
        """Return the abbreviated hash used in finding messages."""
        return self.hash[:SHORT_HASH_LENGTH]


def clone_history(
    name: str,
    *,
    n: int = 10,
    timeout: float = GIT_TIMEOUT_SECONDS,
    _git_url: str | None = None,
) -> list[Commit]:
    """Clone ``name`` and return its newest ``n`` commits, newest first.

    The clone fetches ``n + 1`` commits so the oldest returned commit still has
    a parent to diff against. ``timeout`` applies to the clone; ``_git_url``
    exists only for tests.
    """
    validate_package_name(name)
    if n < 1:
        return []

    with tempfile.TemporaryDirectory(prefix="aurscan-history-") as temporary:
        clone_dir = Path(temporary) / name
        try:
            clone_package(
                name,
                clone_dir,
                timeout=timeout,
                url=_git_url,
                depth=n + 1,
            )
        except AurscanError as exc:
            raise HistoryError(f"could not clone history for {name}: {exc.message}") from exc

        records = _log_records(clone_dir, n + 1)
        if not records:
            raise HistoryError(f"no commits found for {name}")

        commits: list[Commit] = []
        for index, (hash_value, author, date, message) in enumerate(records[:n]):
            parent = records[index + 1][0] if index + 1 < len(records) else None
            commits.append(
                _build_commit(
                    clone_dir,
                    hash_value=hash_value,
                    parent=parent,
                    author=author,
                    date=date,
                    message=message,
                )
            )
        return commits


def diff_findings(commits: Sequence[Commit], rules: RuleRegistry) -> list[Finding]:
    """Run content rules against lines added by each commit.

    Every commit carries the full snapshot of its changed content files. Rules
    run on that snapshot and findings are kept only when their line is one of the
    lines the commit added, so pre-existing suspicious code is not re-reported.
    """
    findings: list[Finding] = []
    for commit in commits:
        if not commit.added_lines:
            continue
        context = _commit_context(commit)
        for item in rules.run_all(context):
            if item.line is None:
                continue
            if item.line not in commit.added_lines.get(item.file, ()):
                continue
            findings.append(
                item.model_copy(
                    update={
                        "message": f"new in commit {commit.short_hash}: {item.message}",
                        "source": "history",
                    }
                )
            )
    return sort_findings(dedupe_findings(findings))


def maintainer_change_findings(
    commits: Sequence[Commit], meta: PackageInfo | None
) -> list[Finding]:
    """Flag a recent author change on a package that is currently orphaned.

    AUR only exposes the current maintainer, so ``maintainer is None`` is the
    available "previously orphaned" signal.
    """
    if meta is None or meta.maintainer is not None or len(commits) < 2:
        return []

    authors = [commit.author for commit in commits]
    if not any(
        previous != current
        for previous, current in zip(authors, authors[1:], strict=False)
    ):
        return []

    latest = sanitize_text(commits[0].author, max_length=100) or "unknown"
    return [
        finding(
            "M01",
            Severity.MEDIUM,
            "git authors changed in recent commits while the package is orphaned "
            f"(latest author: {latest})",
            METADATA_FILE,
            source="history",
        )
    ]


def _build_commit(
    repo: Path,
    *,
    hash_value: str,
    parent: str | None,
    author: str,
    date: datetime,
    message: str,
) -> Commit:
    tree_files = _tree_files(repo, hash_value)
    changed = _changed_files(repo, hash_value)
    added_lines = _added_lines(_diff(repo, parent, hash_value)) if parent is not None else {}
    content = _content_snapshot(repo, hash_value, changed, set(tree_files))
    return Commit(
        hash=hash_value,
        author=sanitize_text(author, max_length=200) or "unknown",
        date=date,
        message=sanitize_text(message, max_length=500),
        files=changed,
        added_lines=added_lines,
        content=content,
        tree_files=tree_files,
    )


def _log_records(repo: Path, limit: int) -> list[tuple[str, str, datetime, str]]:
    """Return ``(hash, author, date, message)`` records, newest first."""
    raw = _run_git(
        repo,
        "log",
        f"--max-count={limit}",
        "--format=%H%x00%an%x00%aI%x00%B%x00",
    )
    fields = raw.split("\x00")
    records: list[tuple[str, str, datetime, str]] = []
    for index in range(0, len(fields) - 3, 4):
        hash_value = fields[index].strip()
        if not hash_value:
            continue
        author = fields[index + 1].strip()
        date_text = fields[index + 2].strip()
        message = fields[index + 3].strip()
        try:
            date = datetime.fromisoformat(date_text)
        except ValueError as exc:
            raise HistoryError(f"invalid commit date for {hash_value[:SHORT_HASH_LENGTH]}") from exc
        records.append((hash_value, author, date, message))
    return records


def _tree_files(repo: Path, hash_value: str) -> list[str]:
    raw = _run_git(repo, "ls-tree", "-r", "-z", "--name-only", "--full-tree", hash_value)
    return [item for item in raw.split("\x00") if item]


def _changed_files(repo: Path, hash_value: str) -> list[str]:
    raw = _run_git(
        repo,
        "diff-tree",
        "--root",
        "--no-commit-id",
        "--name-only",
        "-r",
        "--no-renames",
        "-z",
        hash_value,
    )
    return [item for item in raw.split("\x00") if item]


def _diff(repo: Path, parent: str, hash_value: str) -> str:
    return _run_git(
        repo,
        "diff",
        "--unified=0",
        "--no-color",
        "--no-ext-diff",
        "--no-renames",
        parent,
        hash_value,
        "--",
    )


def _added_lines(patch: str) -> dict[str, list[int]]:
    """Parse a unified diff and return added line numbers per path."""
    added: dict[str, list[int]] = {}
    current: str | None = None
    next_line = 0

    for line in patch.splitlines():
        if line.startswith("+++ "):
            target = line[4:].strip()
            if target == "/dev/null":
                current = None
                continue
            current = target[2:] if target.startswith("b/") else target
            added.setdefault(current, [])
            continue
        if line.startswith("@@ "):
            match = _HUNK_RE.match(line)
            if match is not None and current is not None:
                next_line = int(match.group(1))
            continue
        if current is None:
            continue
        if line.startswith("+"):
            added[current].append(next_line)
            next_line += 1
        elif line.startswith(" "):
            next_line += 1

    return {path: lines for path, lines in added.items() if lines}


def _content_snapshot(
    repo: Path,
    hash_value: str,
    changed: Sequence[str],
    tree_files: set[str],
) -> dict[str, str]:
    """Read changed content files at ``hash_value`` for rule parsing."""
    content: dict[str, str] = {}
    for path in changed:
        if not _is_content_file(path) or path not in tree_files:
            continue
        text = _show_blob(repo, hash_value, path)
        if text is not None:
            content[path] = text
    return content


def _is_content_file(path: str) -> bool:
    return path == PKGBUILD_FILENAME or (
        path.endswith(INSTALL_SUFFIX) and "/" not in path
    )


def _show_blob(repo: Path, hash_value: str, path: str) -> str | None:
    """Return a blob's text, or ``None`` when it is binary or too large."""
    try:
        text = _run_git(repo, "show", f"{hash_value}:{path}")
    except HistoryError:
        return None
    if "\x00" in text:
        return None
    if len(text.encode("utf-8", errors="replace")) > MAX_CONTENT_BYTES:
        return None
    return text


def _commit_context(commit: Commit) -> RuleContext:
    pkgbuild = None
    raw_pkgbuild = commit.content.get(PKGBUILD_FILENAME)
    if raw_pkgbuild is not None:
        pkgbuild = parse_pkgbuild(raw_pkgbuild).pkgbuild

    install_scripts = []
    for path, text in commit.content.items():
        if path == PKGBUILD_FILENAME or not path.endswith(INSTALL_SUFFIX):
            continue
        install_scripts.extend(parse_install_script(text, path).install_scripts)

    return RuleContext(
        pkgbuild=pkgbuild,
        install_scripts=tuple(install_scripts),
        meta=None,
        cloned_files=tuple(commit.tree_files),
    )


def _run_git(repo: Path, *args: str) -> str:
    """Run a hardened, non-interactive git command and return stdout."""
    command = [
        "git",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.quotePath=false",
        *args,
    ]
    try:
        completed = subprocess.run(
            command,
            cwd=repo,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=GIT_TIMEOUT_SECONDS,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
            env=git_env(),
        )
    except FileNotFoundError as exc:
        raise HistoryError("git executable not found") from exc
    except subprocess.TimeoutExpired as exc:
        raise HistoryError(
            f"git command timed out after {GIT_TIMEOUT_SECONDS:g} seconds"
        ) from exc

    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise HistoryError(f"git command failed: {detail[:500]}")
    return completed.stdout
