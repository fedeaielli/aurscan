"""Command-line interface for aurscan."""

from __future__ import annotations

import json
import sys
from collections.abc import Sequence
from typing import NoReturn

import typer
from rich.console import Console

from aurscan.cache import ResponseCache, default_cache_dir
from aurscan.deps import (
    DEFAULT_DEPTH,
    DEFAULT_MAX_DEPS,
    MAX_DEPTH,
    scan_dependencies,
)
from aurscan.errors import AurscanError, ExitCode
from aurscan.fetch import fetch_meta
from aurscan.history import diff_findings, maintainer_change_findings
from aurscan.models import Verdict
from aurscan.pipeline import parse_package_with_history
from aurscan.report import build_report, highest_verdict, render_human, render_json
from aurscan.rules import RuleContext, registry
from aurscan.scoring import load_scoring_config
from aurscan.validation import sanitize_text, validate_package_name

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Static risk scanner for AUR packages.",
)

_VERDICT_EXIT_CODES: dict[Verdict, ExitCode] = {
    Verdict.OK: ExitCode.OK,
    Verdict.REVIEW: ExitCode.REVIEW,
    Verdict.RISKY: ExitCode.RISKY,
}


class _CommandExit(Exception):
    """Carry an exit code past Click without colliding with its usage-error code 2."""

    def __init__(self, code: int) -> None:
        super().__init__(code)
        self.code = code


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
    package: str | None = typer.Argument(None, help="AUR package name"),
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
    explain: str | None = typer.Option(
        None,
        "--explain",
        metavar="RULE_ID",
        help="Print the full description of RULE_ID and exit",
    ),
) -> None:
    """Fetch, parse, and analyse PACKAGE, then print a risk report."""
    if explain is not None:
        raise _CommandExit(_explain_rule(explain))
    if package is None:
        typer.echo("aurscan: error: missing package name", err=True)
        raise _CommandExit(int(ExitCode.ERROR))
    try:
        name = validate_package_name(package)
        cache = None if no_cache else ResponseCache(default_cache_dir())
        info = fetch_meta(name, timeout=timeout, cache=cache)
        parse_result, commits = parse_package_with_history(
            name, timeout=timeout, include_history=not no_history
        )
        context = RuleContext(
            pkgbuild=parse_result.pkgbuild,
            install_scripts=tuple(parse_result.install_scripts),
            meta=info,
            cloned_files=tuple(parse_result.cloned_files),
        )
        findings = registry.run_all(context)
        if commits:
            findings.extend(diff_findings(commits, registry))
            findings.extend(maintainer_change_findings(commits, info))
        config = load_scoring_config()
        report = build_report(info, parse_result, findings, config=config)
        if deps:
            report.dependencies = scan_dependencies(
                report,
                depth,
                include_make=include_make,
                max_deps=max_deps,
                timeout=timeout,
                cache=cache,
            )
        if json_output:
            typer.echo(render_json(report))
        else:
            render_human(report, Console(), config=config)
        raise _CommandExit(int(_VERDICT_EXIT_CODES[highest_verdict(report)]))
    except AurscanError as exc:
        message = sanitize_text(str(exc), max_length=500) or exc.__class__.__name__
        if json_output:
            typer.echo(json.dumps({"error": message}, ensure_ascii=False))
        else:
            typer.echo(f"aurscan: error: {message}", err=True)
        raise _CommandExit(int(ExitCode.ERROR)) from exc


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return an exit code. Usage errors map to 3, not 2."""
    args = list(argv) if argv is not None else None
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
