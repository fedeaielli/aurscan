"""Clone-to-parse orchestration for a single AUR package."""

from __future__ import annotations

import tempfile
from pathlib import Path, PurePosixPath

from aurscan.clone import DEFAULT_TIMEOUT_SECONDS, clone_package
from aurscan.errors import AurscanError, CloneResourceError
from aurscan.history import HISTORY_COMMITS, Commit, read_commits
from aurscan.models import ParseResult
from aurscan.parse import parse_install_script, parse_pkgbuild
from aurscan.safepaths import iter_regular_files, read_text_safe
from aurscan.shell import expand_variables
from aurscan.validation import validate_package_name

PKGBUILD_FILENAME = "PKGBUILD"
_INSTALL_SUFFIX = ".install"


def parse_package(
    name: str,
    *,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    _git_url: str | None = None,
) -> ParseResult:
    """Clone ``name`` and parse its PKGBUILD and install scripts.

    Expected failures (clone, unsafe paths, missing/binary files) are recorded in
    ``ParseResult.errors`` instead of being raised: one bad file must not abort
    the scan. ``_git_url`` exists only for tests and points at a local repository.
    """
    result, _ = parse_package_with_history(
        name,
        timeout=timeout,
        include_history=False,
        _git_url=_git_url,
    )
    return result


def parse_package_with_history(
    name: str,
    *,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    history_commits: int = HISTORY_COMMITS,
    include_history: bool = True,
    _git_url: str | None = None,
) -> tuple[ParseResult, list[Commit]]:
    """Clone ``name`` once and return the parsed package and its newest commits.

    One clone feeds both the content rules and the history rules: it fetches
    ``history_commits + 1`` commits when history is enabled (the oldest returned
    commit needs a parent to diff against) and only the tip with
    ``include_history=False``. A clone that exceeds the size limit or times out
    is retried once at depth 1: content analysis still runs, history is skipped
    with a note. Other clone errors are not retried. ``_git_url`` exists only
    for tests.
    """
    validate_package_name(name)
    depth = max(1, history_commits + 1) if include_history else 1
    with tempfile.TemporaryDirectory(prefix="aurscan-") as temporary:
        clone_dir = Path(temporary) / name
        try:
            clone_package(name, clone_dir, timeout=timeout, url=_git_url, depth=depth)
        except CloneResourceError as exc:
            if depth <= 1:
                return _clone_failure_result(name, exc), []
            retry_dir = Path(temporary) / f"{name}-content"
            try:
                clone_package(
                    name, retry_dir, timeout=timeout, url=_git_url, depth=1
                )
            except AurscanError as retry_exc:
                return _clone_failure_result(name, retry_exc), []
            result = _parse_clone_dir(name, retry_dir)
            result.errors.append(f"history skipped: {exc.message}")
            return result, []
        except AurscanError as exc:
            return _clone_failure_result(name, exc), []

        result = _parse_clone_dir(name, clone_dir)
        if not include_history:
            return result, []

        try:
            commits = read_commits(clone_dir, n=history_commits, label=name)
        except AurscanError as exc:
            # History is an enhancement: a git failure must not abort the scan.
            result.errors.append(f"history analysis failed: {exc.message}")
            return result, []
        return result, commits


def _clone_failure_result(name: str, exc: AurscanError) -> ParseResult:
    """Return the metadata-only result used when the content clone fails."""
    return _failed_result(
        f"Could not clone repo for {name} — analysis based on metadata only "
        f"({exc.message})"
    )


def _parse_clone_dir(name: str, clone_dir: Path) -> ParseResult:
    """Parse the PKGBUILD and install scripts of an existing clone."""
    try:
        pkgbuild_source = read_text_safe(clone_dir, PKGBUILD_FILENAME)
    except AurscanError as exc:
        return _failed_result(
            f"Could not read {PKGBUILD_FILENAME} for {name} — "
            f"analysis based on metadata only ({exc.message})"
        )

    result = parse_pkgbuild(pkgbuild_source)
    errors = list(result.errors)
    install_scripts = list(result.install_scripts)
    findings = list(result.findings)
    parse_failed = result.parse_failed
    if parse_failed:
        errors.append(
            f"Could not fully parse {PKGBUILD_FILENAME} for {name} — "
            "analysis may be incomplete"
        )

    files = _list_files(clone_dir, errors)
    cloned_files = _relative_files(clone_dir, files)

    for relative in _install_candidates(result, files, clone_dir):
        try:
            source = read_text_safe(clone_dir, relative)
        except AurscanError as exc:
            errors.append(f"Could not read {relative} — skipped ({exc.message})")
            continue
        parsed = parse_install_script(source, relative)
        install_scripts.extend(parsed.install_scripts)
        findings.extend(parsed.findings)
        errors.extend(parsed.errors)
        if parsed.parse_failed:
            errors.append(f"Could not fully parse {relative} — analysis may be incomplete")
        parse_failed = parse_failed or parsed.parse_failed

    return ParseResult(
        pkgbuild=result.pkgbuild,
        install_scripts=install_scripts,
        parse_failed=parse_failed,
        findings=findings,
        errors=errors,
        cloned_files=cloned_files,
    )


def _list_files(clone_dir: Path, errors: list[str]) -> list[Path]:
    try:
        return list(iter_regular_files(clone_dir))
    except AurscanError as exc:
        errors.append(
            f"Could not list cloned files — analysis may be incomplete ({exc.message})"
        )
        return []


def _relative_files(clone_dir: Path, files: list[Path]) -> list[str]:
    """Return regular files as POSIX paths relative to the clone root."""
    root = clone_dir.resolve()
    relatives: list[str] = []
    for path in files:
        try:
            relative = path.relative_to(root)
        except ValueError:
            continue
        if relative.parts and relative.parts[0] == ".git":
            continue
        relatives.append(relative.as_posix())
    return relatives


def _install_candidates(
    result: ParseResult,
    files: list[Path],
    clone_dir: Path,
) -> list[str]:
    """Return install-script paths: the declared file plus top-level ``*.install``."""
    candidates: list[str] = []
    pkgbuild = result.pkgbuild
    if pkgbuild is not None and pkgbuild.install:
        declared = PurePosixPath(
            expand_variables(pkgbuild.install, pkgbuild.variables)
        ).as_posix()
        if declared and declared != ".":
            candidates.append(declared)

    root = clone_dir.resolve()
    for path in files:
        try:
            relative = path.relative_to(root)
        except ValueError:
            continue
        if len(relative.parts) != 1 or not relative.name.endswith(_INSTALL_SUFFIX):
            continue
        candidates.append(relative.as_posix())

    return list(dict.fromkeys(candidates))


def _failed_result(message: str) -> ParseResult:
    return ParseResult(
        pkgbuild=None,
        install_scripts=[],
        parse_failed=True,
        errors=[message],
    )
