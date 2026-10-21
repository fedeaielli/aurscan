"""Command-line interface for aurscan."""

from __future__ import annotations

import json
import sys
from collections.abc import Sequence
from datetime import datetime
from typing import NoReturn

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from aurscan.errors import AurscanError, ExitCode
from aurscan.fetch import fetch_meta
from aurscan.models import PackageInfo
from aurscan.validation import sanitize_text, validate_package_name

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Static risk scanner for AUR packages.",
)


def _format_datetime(value: datetime) -> str:
    return value.strftime("%Y-%m-%d %H:%M UTC")


def _value(text: str | None, *, placeholder: str = "—", max_length: int = 300) -> Text:
    if not text:
        return Text(placeholder, style="dim")
    cleaned = sanitize_text(text, max_length=max_length)
    return Text(cleaned or placeholder, style="dim" if not cleaned else "")


def _render_metadata(info: PackageInfo, console: Console) -> None:
    header = Text("aurscan: ", style="bold")
    header.append(sanitize_text(info.name, max_length=255), style="bold")
    header.append("  (version ")
    header.append(sanitize_text(info.version, max_length=100))
    header.append(")")
    console.print(header)

    table = Table(show_header=False, box=None, pad_edge=False)
    table.add_column(style="cyan", no_wrap=True)
    table.add_column()

    maintainer = (
        _value(info.maintainer) if info.maintainer else Text("orphaned", style="yellow")
    )

    rows: list[tuple[str, Text]] = [
        ("maintainer", maintainer),
        ("submitter", _value(info.submitter)),
        ("first submitted", Text(_format_datetime(info.first_submitted))),
        ("last modified", Text(_format_datetime(info.last_modified))),
        ("votes", Text(str(info.num_votes))),
        ("popularity", Text(f"{info.popularity:.2f}")),
        (
            "out of date",
            Text("yes", style="yellow")
            if info.out_of_date
            else Text("no", style="green"),
        ),
        ("url", _value(info.url)),
        ("depends", _value(", ".join(info.depends))),
        ("make depends", _value(", ".join(info.make_depends))),
        ("opt depends", _value(", ".join(info.opt_depends))),
    ]
    if info.out_of_date:
        rows.insert(7, ("out of date since", Text(_format_datetime(info.out_of_date))))

    for label, value in rows:
        table.add_row(label, value)
    console.print(table)


@app.command()
def scan(
    package: str = typer.Argument(..., help="AUR package name"),
    timeout: float = typer.Option(10.0, "--timeout", min=1.0, help="HTTP timeout in seconds"),
    json_output: bool = typer.Option(False, "--json", help="Emit JSON instead of a table"),
) -> None:
    """Fetch AUR metadata for PACKAGE."""
    try:
        name = validate_package_name(package)
        info = fetch_meta(name, timeout=timeout)
        if json_output:
            typer.echo(json.dumps(info.model_dump(mode="json"), indent=2, ensure_ascii=False))
        else:
            _render_metadata(info, Console())
    except AurscanError as exc:
        message = sanitize_text(str(exc), max_length=500) or exc.__class__.__name__
        if json_output:
            typer.echo(json.dumps({"error": message}, ensure_ascii=False))
        else:
            typer.echo(f"aurscan: error: {message}", err=True)
        raise typer.Exit(code=int(ExitCode.ERROR)) from exc


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI and return an exit code. Usage errors map to 3, not 2."""
    args = list(argv) if argv is not None else None
    try:
        app(args=args)
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else int(ExitCode.ERROR)
        if code == 2:
            return int(ExitCode.ERROR)
        return code
    return int(ExitCode.OK)


def run() -> NoReturn:
    sys.exit(main())
