"""Optional AUR dependency resolution and scanning.

Dependency names come from AUR metadata. Version constraints are stripped and
only names the AUR actually hosts are scanned; packages that live only in the
official repositories are silently skipped. Nothing here executes package
content: dependencies go through the same clone/parse/static-rule pipeline as
the root package and never run git history analysis.
"""

from __future__ import annotations

import re
import time
from collections import deque
from collections.abc import Callable
from functools import partial

from aurscan.cache import ResponseCache
from aurscan.errors import AurscanError, InvalidPackageNameError
from aurscan.fetch import fetch_meta_many
from aurscan.models import PackageInfo, Report, Verdict
from aurscan.pipeline import parse_package
from aurscan.report import build_report
from aurscan.rules import RuleContext, registry
from aurscan.validation import validate_package_name

DEFAULT_DEPTH = 1
MAX_DEPTH = 5
DEFAULT_MAX_DEPS = 20
REQUEST_PAUSE_SECONDS = 1.0

FetchFunc = Callable[[str], PackageInfo | None]
AnalyzeFunc = Callable[[PackageInfo], Report]
SleepFunc = Callable[[float], None]


def resolve_aur_deps(meta: PackageInfo, include_make: bool = False) -> list[str]:
    """Return candidate dependency names, without constraints, in declared order.

    ``meta.depends`` is always considered; ``meta.make_depends`` is added when
    ``include_make`` is true. Names that cannot be valid AUR package names, the
    package itself, and duplicates are dropped. Whether a name really exists in
    the AUR is decided by the metadata lookup in :func:`scan_dependencies`.
    """
    entries = [*meta.depends]
    if include_make:
        entries.extend(meta.make_depends)

    names: list[str] = []
    seen: set[str] = {meta.name}
    for entry in entries:
        name = _dependency_name(entry)
        if name is None or name in seen:
            continue
        seen.add(name)
        names.append(name)
    return names


def analyze_package(
    meta: PackageInfo,
    *,
    timeout: float = 10.0,
) -> Report:
    """Analyse one dependency using static and metadata rules only."""
    parse_result = parse_package(meta.name, timeout=timeout)
    context = RuleContext(
        pkgbuild=parse_result.pkgbuild,
        install_scripts=tuple(parse_result.install_scripts),
        meta=meta,
        cloned_files=tuple(parse_result.cloned_files),
    )
    return build_report(meta, parse_result, registry.run_all(context))


def scan_dependencies(
    root_report: Report,
    depth: int = DEFAULT_DEPTH,
    *,
    include_make: bool = False,
    max_deps: int = DEFAULT_MAX_DEPS,
    timeout: float = 10.0,
    cache: ResponseCache | None = None,
    sleep: SleepFunc | None = None,
    _fetch: FetchFunc | None = None,
    _analyze: AnalyzeFunc | None = None,
) -> list[Report]:
    """Scan up to ``depth`` levels of AUR dependencies and return the top level.

    Traversal is breadth-first. A visited set keyed by package name prevents
    cycles and duplicate work. At least one second is paused before every
    metadata request. A dependency that is not in the AUR is skipped, while a
    failed lookup or analysis is recorded and the scan continues.
    """
    if not 1 <= depth <= MAX_DEPTH:
        raise ValueError(f"depth must be between 1 and {MAX_DEPTH}")
    if max_deps < 0:
        raise ValueError("max_deps must not be negative")

    pause = sleep if sleep is not None else _sleep
    fetch = _fetch if _fetch is not None else partial(_fetch_meta, timeout=timeout, cache=cache)
    analyze = _analyze if _analyze is not None else partial(analyze_package, timeout=timeout)

    visited: set[str] = {root_report.package.name}
    scanned: list[Report] = []
    top_level: list[Report] = []
    queue: deque[tuple[Report, int]] = deque([(root_report, 0)])
    truncated = False

    while queue and not truncated:
        parent, level = queue.popleft()
        if level >= depth:
            continue
        for name in resolve_aur_deps(parent.package, include_make):
            if name in visited:
                continue
            if len(scanned) >= max_deps:
                truncated = True
                break

            visited.add(name)
            pause(REQUEST_PAUSE_SECONDS)
            try:
                meta = fetch(name)
            except AurscanError as exc:
                root_report.errors.append(
                    f"dependency {name}: metadata unavailable: {exc.message}"
                )
                continue
            if meta is None:
                continue

            try:
                report = analyze(meta)
            except AurscanError as exc:
                report = _failed_report(meta, message=exc.message)

            report = report.model_copy(
                update={"dependencies": [], "dep_of": parent.package.name}
            )
            scanned.append(report)
            if level == 0:
                top_level.append(report)
            else:
                parent.dependencies.append(report)
            queue.append((report, level + 1))

    if truncated:
        root_report.errors.append(f"dependency scan truncated at {max_deps} packages")
    return top_level


def _dependency_name(entry: str) -> str | None:
    """Strip a version constraint or description and validate the name."""
    token = re.split(r"[<>=:]", entry, maxsplit=1)[0].strip()
    if not token:
        return None
    try:
        return validate_package_name(token)
    except InvalidPackageNameError:
        return None


def _fetch_meta(
    name: str, *, timeout: float, cache: ResponseCache | None
) -> PackageInfo | None:
    """Return metadata for one package, or ``None`` when the AUR does not host it."""
    return fetch_meta_many([name], timeout=timeout, cache=cache).get(name)


def _failed_report(meta: PackageInfo, *, message: str) -> Report:
    return Report(
        package=meta,
        findings=[],
        score=0,
        verdict=Verdict.OK,
        errors=[message],
        dependencies=[],
        dep_of=None,
    )


def _sleep(seconds: float) -> None:
    """Indirection kept small so tests never wait on the real clock."""
    time.sleep(seconds)
