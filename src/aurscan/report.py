"""Report construction and rendering (rich and JSON)."""

from __future__ import annotations

import json
from collections import deque
from collections.abc import Iterator, Sequence
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

_VERDICT_ORDER: dict[Verdict, int] = {
    Verdict.OK: 0,
    Verdict.REVIEW: 1,
    Verdict.RISKY: 2,
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


def highest_verdict(report: Report) -> Verdict:
    """Return the highest verdict among ``report`` and its dependencies."""
    return max(
        (item.verdict for item in iter_reports(report)),
        key=_VERDICT_ORDER.__getitem__,
    )


def iter_reports(report: Report) -> Iterator[Report]:
    """Yield ``report`` and every nested dependency breadth-first."""
    queue: deque[Report] = deque([report])
    while queue:
        current = queue.popleft()
        yield current
        queue.extend(current.dependencies)


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

    if report.dependencies:
        _render_dependencies(report.dependencies, console)

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


def _render_dependencies(dependencies: Sequence[Report], console: Console) -> None:
    console.print()
    console.print(Text("Dependencies", style="bold"))
    table = Table(box=None, pad_edge=False)
    table.add_column("name", no_wrap=True)
    table.add_column("parent", no_wrap=True)
    table.add_column("depth", justify="right", no_wrap=True)
    table.add_column("score", justify="right", no_wrap=True)
    table.add_column("verdict", no_wrap=True)

    highest: Report | None = None
    for dependency, depth in _walk_dependencies(dependencies):
        table.add_row(
            Text(_safe(dependency.package.name, 255)),
            Text(_safe(dependency.dep_of or "\u2014", 255)),
            Text(str(depth)),
            Text(str(dependency.score)),
            Text(dependency.verdict.value, style=_VERDICT_STYLES[dependency.verdict]),
        )
        if highest is None or dependency.score > highest.score:
            highest = dependency
    console.print(table)

    if highest is not None:
        console.print(
            Text(
                "Highest dependency risk: "
                f"{_safe(highest.package.name, 255)} ({highest.score})"
            )
        )

    notes = [
        (dependency.package.name, error)
        for dependency, _depth in _walk_dependencies(dependencies)
        for error in dependency.errors
    ]
    if notes:
        console.print()
        console.print(Text("Dependency notes", style="bold yellow"))
        for name, error in notes:
            console.print(f"  {_safe(name, 255)}: {_safe(error, 500)}", style="yellow")


def _walk_dependencies(
    dependencies: Sequence[Report], depth: int = 1
) -> Iterator[tuple[Report, int]]:
    queue: deque[tuple[Report, int]] = deque((item, depth) for item in dependencies)
    while queue:
        dependency, level = queue.popleft()
        yield dependency, level
        queue.extend((child, level + 1) for child in dependency.dependencies)


def _format_datetime(value: datetime) -> str:
    return value.strftime("%Y-%m-%d %H:%M UTC")


def _value(text: str | None, *, placeholder: str = "\u2014", max_length: int = 300) -> Text:
    if not text:
        return Text(placeholder, style="dim")
    cleaned = _safe(text, max_length)
    return Text(cleaned or placeholder, style="dim" if not cleaned else "")


def _safe(text: str, max_length: int) -> str:
    return sanitize_text(text, max_length=max_length)
