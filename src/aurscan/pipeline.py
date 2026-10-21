"""Clone-to-parse orchestration for a single AUR package."""

from __future__ import annotations

import tempfile
from pathlib import Path

from aurscan.clone import DEFAULT_TIMEOUT_SECONDS, clone_package
from aurscan.errors import AurscanError
from aurscan.models import ParseResult
from aurscan.parse import parse_install_script, parse_pkgbuild
from aurscan.safepaths import iter_regular_files, read_text_safe
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
    validate_package_name(name)
    with tempfile.TemporaryDirectory(prefix="aurscan-") as temporary:
        clone_dir = Path(temporary) / name
        try:
            clone_package(name, clone_dir, timeout=timeout, url=_git_url)
        except AurscanError as exc:
            return _failed_result(f"could not clone {name}: {exc.message}")

        try:
            pkgbuild_source = read_text_safe(clone_dir, PKGBUILD_FILENAME)
        except AurscanError as exc:
            return _failed_result(f"could not read {PKGBUILD_FILENAME}: {exc.message}")

        result = parse_pkgbuild(pkgbuild_source)
        errors = list(result.errors)
        install_scripts = list(result.install_scripts)
        findings = list(result.findings)
        parse_failed = result.parse_failed

        for relative in _install_candidates(clone_dir, result, errors):
            try:
                source = read_text_safe(clone_dir, relative)
            except AurscanError as exc:
                errors.append(f"could not read {relative}: {exc.message}")
                continue
            parsed = parse_install_script(source, relative)
            install_scripts.extend(parsed.install_scripts)
            findings.extend(parsed.findings)
            errors.extend(parsed.errors)
            parse_failed = parse_failed or parsed.parse_failed

        return ParseResult(
            pkgbuild=result.pkgbuild,
            install_scripts=install_scripts,
            parse_failed=parse_failed,
            findings=findings,
            errors=errors,
        )


def _install_candidates(
    clone_dir: Path,
    result: ParseResult,
    errors: list[str],
) -> list[str]:
    """Return install-script paths: the declared file plus top-level ``*.install``."""
    candidates: list[str] = []
    declared = result.pkgbuild.install if result.pkgbuild is not None else None
    if declared:
        candidates.append(declared)

    root = clone_dir.resolve()
    try:
        files = list(iter_regular_files(clone_dir))
    except AurscanError as exc:
        errors.append(f"could not list cloned files: {exc.message}")
        files = []

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
