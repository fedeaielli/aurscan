"""Command-line interface for aurscan."""

from __future__ import annotations

import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import NoReturn

import typer
from rich.console import Console

from aurscan import __version__
from aurscan.cache import ResponseCache, default_cache_dir
from aurscan.deps import (
    DEFAULT_DEPTH,
    DEFAULT_MAX_DEPS,
    MAX_DEPTH,
    scan_dependencies,
)
from aurscan.errors import AurscanError, ExitCode, LocalPathError
from aurscan.fetch import fetch_meta
from aurscan.history import Commit, diff_findings, maintainer_change_findings
from aurscan.models import (
    Finding,
    PackageInfo,
    ParseResult,
    Report,
    Severity,
    Verdict,
)
from aurscan.pipeline import parse_local_directory, parse_package_with_history
from aurscan.report import (
    build_report,
    highest_verdict,
    render_human,
    render_json,
    render_rule_catalogue,
)
from aurscan.rules import RuleContext, registry
from aurscan.scoring import ScoringConfig, load_scoring_config
from aurscan.validation import sanitize_text, validate_package_name

app = typer.Typer(
    add_completion=False,
    help="Static risk scanner for AUR packages.",
)

_VERDICT_EXIT_CODES: dict[Verdict, ExitCode] = {
    Verdict.OK: ExitCode.OK,
    Verdict.REVIEW: ExitCode.REVIEW,
    Verdict.RISKY: ExitCode.RISKY,
}

# Hoisted so ruff's B008 does not flag a non-literal enum default.
_MIN_SEVERITY_OPTION = typer.Option(
    Severity.INFO,
    "--min-severity",
    help="Hide findings below this severity (affects score, verdict and exit code)",
)

_LOCAL_OPTION = typer.Option(
    None,
    "--local",
    metavar="PATH",
    help="Scan a local directory containing a PKGBUILD (no network)",
)

_PACKAGES_ARGUMENT = typer.Argument(None, help="AUR package names")


class _CommandExit(Exception):
    """Carry an exit code past Click without colliding with its usage-error code 2."""

    def __init__(self, code: int) -> None:
        super().__init__(code)
        self.code = code


def _collect_findings(
    parse_result: ParseResult,
    commits: Sequence[Commit],
    *,
    info: PackageInfo,
    meta: PackageInfo | None,
) -> list[Finding]:
    """Run the content rules, plus history rules when commits were read.

    ``meta`` is passed separately so a local scan can keep synthetic metadata
    for the report while silencing the AUR-only metadata rules.
    """
    context = RuleContext(
        pkgbuild=parse_result.pkgbuild,
        install_scripts=tuple(parse_result.install_scripts),
        meta=meta,
        cloned_files=tuple(parse_result.cloned_files),
    )
    findings = registry.run_all(context)
    if commits:
        findings.extend(diff_findings(commits, registry))
        findings.extend(maintainer_change_findings(commits, info))
    return findings


def _local_package(parse_result: ParseResult, path: Path) -> PackageInfo:
    """Build the synthetic package header for a local directory scan."""
    pkgbuild = parse_result.pkgbuild
    name = path.name
    version = "unknown"
    if pkgbuild is not None:
        if pkgbuild.pkgname:
            name = pkgbuild.pkgname[0]
        if pkgbuild.pkgver and pkgbuild.pkgrel:
            version = f"{pkgbuild.pkgver}-{pkgbuild.pkgrel}"
        elif pkgbuild.pkgver:
            version = pkgbuild.pkgver
    return PackageInfo.local_stub(name, version=version)


def _scan_remote(
    name: str,
    *,
    config: ScoringConfig,
    timeout: float,
    no_history: bool,
    min_severity: Severity,
    cache: ResponseCache | None,
) -> Report:
    """Fetch, clone, parse, and score one AUR package."""
    name = validate_package_name(name)
    info = fetch_meta(name, timeout=timeout, cache=cache)
    parse_result, commits = parse_package_with_history(
        name, timeout=timeout, include_history=not no_history
    )
    findings = _collect_findings(parse_result, commits, info=info, meta=info)
    return build_report(
        info, parse_result, findings, config=config, min_severity=min_severity
    )


def _scan_local(
    path: Path, *, config: ScoringConfig, min_severity: Severity
) -> Report:
    """Parse and score a local directory without network access."""
    parse_result = parse_local_directory(path)
    parse_result.errors.append(
        "local scan: AUR metadata and history are not available"
    )
    info = _local_package(parse_result, path)
    findings = _collect_findings(parse_result, [], info=info, meta=None)
    return build_report(
        info, parse_result, findings, config=config, min_severity=min_severity
    )


def _error_message(exc: AurscanError) -> str:
    """Return a failure message that is safe to print or serialize."""
    return sanitize_text(str(exc), max_length=500) or exc.__class__.__name__


def _explain_rule(value: str) -> int:
    """Print a rule's full description and return an exit code."""
    rule_id = value.strip().upper()
    info = registry.explain(rule_id)
    if info is None:
        safe = sanitize_text(value, max_length=80) or "?"
        typer.echo(f"aurscan: error: unknown rule: {safe}", err=True)
        return int(ExitCode.ERROR)
    severity, description = info
    typer.echo(f"{rule_id} ({severity.value})")
    typer.echo(description)
    return int(ExitCode.OK)


@app.command()
def scan(
    packages: list[str] | None = _PACKAGES_ARGUMENT,
    local_path: Path | None = _LOCAL_OPTION,
    timeout: float = typer.Option(10.0, "--timeout", min=1.0, help="Network timeout in seconds"),
    json_output: bool = typer.Option(False, "--json", help="Emit JSON instead of a table"),
    no_cache: bool = typer.Option(False, "--no-cache", help="Bypass the on-disk HTTP cache"),
    no_history: bool = typer.Option(
        False, "--no-history", help="Skip git history analysis"
    ),
    deps: bool = typer.Option(False, "--deps", help="Also scan AUR dependencies"),
    depth: int = typer.Option(
        DEFAULT_DEPTH,
        "--depth",
        min=1,
        max=MAX_DEPTH,
        help=f"Dependency depth to scan (max {MAX_DEPTH})",
    ),
    include_make: bool = typer.Option(
        False, "--include-make", help="Include makedepends when scanning dependencies"
    ),
    max_deps: int = typer.Option(
        DEFAULT_MAX_DEPS,
        "--max-deps",
        min=0,
        help="Maximum number of dependencies to scan",
    ),
    min_severity: Severity = _MIN_SEVERITY_OPTION,
    version: bool = typer.Option(
        False, "--version", help="Print the aurscan version and exit"
    ),
    rules: bool = typer.Option(
        False,
        "--rules",
        help="List every rule with its severity and summary, then exit",
    ),
    explain: str | None = typer.Option(
        None,
        "--explain",
        metavar="RULE_ID",
        help="Print the full description of RULE_ID and exit",
    ),
) -> None:
    """Fetch or read PACKAGES / --local PATH, analyse each, and print a report per package."""
    if version:
        typer.echo(f"aurscan {__version__}")
        raise _CommandExit(int(ExitCode.OK))
    if rules:
        render_rule_catalogue(registry.catalogue(), Console())
        raise _CommandExit(int(ExitCode.OK))
    if explain is not None:
        raise _CommandExit(_explain_rule(explain))
    try:
        names = list(packages or [])
        if local_path is not None:
            local_path = local_path.resolve()
            if names:
                raise LocalPathError("--local cannot be combined with a package name")
            if deps:
                raise LocalPathError("--deps is not supported with --local")
        elif not names:
            typer.echo(
                "aurscan: error: missing package name or --local PATH", err=True
            )
            raise _CommandExit(int(ExitCode.ERROR))

        config = load_scoring_config()
        cache: ResponseCache | None = (
            None if no_cache else ResponseCache(default_cache_dir())
        )
        results: list[tuple[str, Report | str]] = []
        exit_code = int(ExitCode.OK)

        if local_path is not None:
            report = _scan_local(local_path, config=config, min_severity=min_severity)
            results.append((str(local_path), report))
            exit_code = int(_VERDICT_EXIT_CODES[highest_verdict(report)])
        else:
            for name in names:
                label = sanitize_text(name, max_length=255) or "?"
                try:
                    report = _scan_remote(
                        name,
                        config=config,
                        timeout=timeout,
                        no_history=no_history,
                        min_severity=min_severity,
                        cache=cache,
                    )
                    if deps:
                        # shortcut: each root gets its own dependency walk, so a
                        # dependency shared by two roots is scanned twice; share
                        # the visited set across roots if that becomes slow.
                        report.dependencies = scan_dependencies(
                            report,
                            depth,
                            include_make=include_make,
                            max_deps=max_deps,
                            timeout=timeout,
                            min_severity=min_severity,
                            cache=cache,
                        )
                except AurscanError as exc:
                    message = _error_message(exc)
                    if not json_output:
                        typer.echo(f"aurscan: error: {label}: {message}", err=True)
                    results.append((label, message))
                    exit_code = int(ExitCode.ERROR)
                    continue
                results.append((label, report))
                exit_code = max(
                    exit_code, int(_VERDICT_EXIT_CODES[highest_verdict(report)])
                )

        if json_output:
            if len(results) == 1 and isinstance(results[0][1], Report):
                typer.echo(render_json(results[0][1]))
            elif len(results) == 1:
                typer.echo(json.dumps({"error": results[0][1]}, ensure_ascii=False))
            else:
                payload = [
                    outcome.model_dump(mode="json")
                    if isinstance(outcome, Report)
                    else {"package": name, "error": outcome}
                    for name, outcome in results
                ]
                typer.echo(json.dumps(payload, indent=2, ensure_ascii=False))
        else:
            console = Console()
            for index, report in enumerate(
                outcome for _name, outcome in results if isinstance(outcome, Report)
            ):
                if index:
                    console.print()
                render_human(report, console, config=config, local_path=local_path)
        raise _CommandExit(exit_code)
    except AurscanError as exc:
        message = _error_message(exc)
        if json_output:
            typer.echo(json.dumps({"error": message}, ensure_ascii=False))
        else:
            typer.echo(f"aurscan: error: {message}", err=True)
        raise _CommandExit(int(ExitCode.ERROR)) from exc


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return an exit code. Usage errors map to 3, not 2."""
    args = list(argv) if argv is not None else sys.argv[1:]
    if not args:
        args = ["--help"]
    try:
        app(args=args)
    except _CommandExit as exc:
        return exc.code
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else int(ExitCode.ERROR)
        if code == 2:
            return int(ExitCode.ERROR)
        return code
    return int(ExitCode.OK)


def run() -> NoReturn:
    sys.exit(main())
