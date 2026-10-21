"""Command-line interface for aurscan."""

from __future__ import annotations

import json
import sys
from collections.abc import Sequence
from typing import NoReturn

import typer
from rich.console import Console

from aurscan.cache import ResponseCache, default_cache_dir
from aurscan.errors import AurscanError, ExitCode
from aurscan.fetch import fetch_meta
from aurscan.models import Verdict
from aurscan.pipeline import parse_package
from aurscan.report import build_report, render_human, render_json
from aurscan.rules import RuleContext, registry
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


@app.command()
def scan(
    package: str = typer.Argument(..., help="AUR package name"),
    timeout: float = typer.Option(10.0, "--timeout", min=1.0, help="Network timeout in seconds"),
    json_output: bool = typer.Option(False, "--json", help="Emit JSON instead of a table"),
    no_cache: bool = typer.Option(False, "--no-cache", help="Bypass the on-disk HTTP cache"),
) -> None:
    """Fetch, parse, and analyse PACKAGE, then print a risk report."""
    try:
        name = validate_package_name(package)
        cache = None if no_cache else ResponseCache(default_cache_dir())
        info = fetch_meta(name, timeout=timeout, cache=cache)
        parse_result = parse_package(name, timeout=timeout)
        context = RuleContext(
            pkgbuild=parse_result.pkgbuild,
            install_scripts=tuple(parse_result.install_scripts),
            meta=info,
            cloned_files=tuple(parse_result.cloned_files),
        )
        report = build_report(info, parse_result, registry.run_all(context))
        if json_output:
            typer.echo(render_json(report))
        else:
            render_human(report, Console())
        raise _CommandExit(int(_VERDICT_EXIT_CODES[report.verdict]))
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
