"""Report construction and rendering (rich and JSON)."""

from __future__ import annotations

import json
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.text import Text

from aurscan.models import Finding, PackageInfo, ParseResult, Report, Severity, Verdict
from aurscan.rules import dedupe_findings, sort_findings
from aurscan.scoring import ScoringConfig, load_scoring_config, score
from aurscan.validation import sanitize_text

_SEVERITY_STYLES: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

_VERDICT_STYLES: dict[Verdict, str] = {
    Verdict.OK: "green",
    Verdict.REVIEW: "yellow",
    Verdict.RISKY: "bold red",
}


def build_report(
    package: PackageInfo,
    parse_result: ParseResult,
    findings: list[Finding],
    *,
    config: ScoringConfig | None = None,
) -> Report:
    """Combine parse and rule findings, score them, and build a report."""
    combined = sort_findings(
        dedupe_findings([*parse_result.findings, *findings])
    )
    total, verdict = score(combined, config=config)
    return Report(
        package=package,
        findings=combined,
        score=total,
        verdict=verdict,
        errors=list(parse_result.errors),
        dependencies=[],
        dep_of=None,
    )


def render_human(report: Report, console: Console) -> None:
    """Print the human-readable report."""
    _render_header(report.package, console)
    _render_risk(report, console)
    _render_metadata(report.package, console)

    if report.findings:
        _render_findings(report.findings, console)
    else:
        console.print(Text("Findings", style="bold"))
        console.print(Text("  none", style="dim"))

    if report.errors:
        console.print()
        console.print(Text("Analysis notes", style="bold yellow"))
        for error in report.errors:
            console.print(f"  {_safe(error, 500)}", style="yellow")


def render_json(report: Report) -> str:
    """Return the report as machine-readable JSON."""
    return json.dumps(report.model_dump(mode="json"), indent=2, ensure_ascii=False)


def _render_header(info: PackageInfo, console: Console) -> None:
    header = Text("aurscan: ", style="bold")
    header.append(_safe(info.name, 255), style="bold")
    header.append("  (version ")
    header.append(_safe(info.version, 100))
    header.append(")")
    console.print(header)


def _render_risk(report: Report, console: Console) -> None:
    style = _VERDICT_STYLES[report.verdict]
    maximum = load_scoring_config().max_score
    line = Text("Risk: ", style="bold")
    line.append(report.verdict.value.upper(), style=style)
    line.append(f"  ({report.score}/{maximum})")
    console.print(line)


def _render_metadata(info: PackageInfo, console: Console) -> None:
    console.print()
    console.print(Text("Metadata", style="bold"))
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


def _render_findings(findings: list[Finding], console: Console) -> None:
    console.print()
    console.print(Text("Findings", style="bold"))
    table = Table(box=None, pad_edge=False)
    table.add_column("", no_wrap=True)
    table.add_column("rule", no_wrap=True)
    table.add_column("location", no_wrap=True)
    table.add_column("finding")
    for item in findings:
        severity = f"[{item.severity.value.upper()}]"
        location = _safe(item.file, 200)
        if item.line is not None:
            location = f"{location}:{item.line}"
        table.add_row(
            Text(severity, style=_SEVERITY_STYLES[item.severity]),
            Text(item.rule_id),
            Text(location),
            Text(_safe(item.message, 500)),
        )
    console.print(table)


def _format_datetime(value: datetime) -> str:
    return value.strftime("%Y-%m-%d %H:%M UTC")


def _value(text: str | None, *, placeholder: str = "\u2014", max_length: int = 300) -> Text:
    if not text:
        return Text(placeholder, style="dim")
    cleaned = _safe(text, max_length)
    return Text(cleaned or placeholder, style="dim" if not cleaned else "")


def _safe(text: str, max_length: int) -> str:
    return sanitize_text(text, max_length=max_length)
