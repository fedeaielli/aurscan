"""R04-R06: source provenance, transport security, and checksum coverage."""

from __future__ import annotations

from aurscan.models import Finding, Pkgbuild, Severity
from aurscan.rules import RuleContext, register
from aurscan.rules.common import (
    aligned_strong_checksum,
    checksum_arrays,
    finding,
    host_of,
    is_ip_host,
    is_user_content_host,
    is_vcs_source,
    line_of,
    same_domain,
    source_url,
    url_scheme,
)

# Architecture-specific source and checksum variables (source_x86_64, ...) are
# intentionally not consulted in M3; M6 adds explicit tracking for them.


@register("R04", Severity.MEDIUM)
def r04_foreign_source(ctx: RuleContext) -> list[Finding]:
    """Flag HTTP sources whose host differs from the upstream project URL.

    Relative sources and VCS sources are skipped, as is the rule entirely when
    the PKGBUILD has no usable upstream ``url`` to compare against. Known
    user-content hosts are rejected even when they match the upstream domain.
    """
    pkgbuild = ctx.pkgbuild
    if pkgbuild is None or not pkgbuild.url:
        return []
    upstream = host_of(pkgbuild.url)
    if upstream is None:
        return []

    findings: list[Finding] = []
    for source in pkgbuild.source:
        if is_vcs_source(source):
            continue
        host = host_of(source_url(source))
        if host is None:
            continue
        line = _source_line(pkgbuild, source)
        if is_user_content_host(host):
            findings.append(
                finding(
                    "R04",
                    Severity.MEDIUM,
                    f"source is hosted on user-content host {host}",
                    "PKGBUILD",
                    line=line,
                    snippet=source,
                )
            )
        elif not same_domain(host, upstream):
            findings.append(
                finding(
                    "R04",
                    Severity.MEDIUM,
                    f"source host {host} differs from upstream host {upstream}",
                    "PKGBUILD",
                    line=line,
                    snippet=source,
                )
            )
    return findings


@register("R05", Severity.MEDIUM)
def r05_insecure_transport(ctx: RuleContext) -> list[Finding]:
    """Flag sources fetched over plain HTTP or from a literal IP address.

    The severity drops to low only when a strong checksum is aligned with the
    source *and* the host is trusted by R04 (same domain as the upstream URL).
    """
    pkgbuild = ctx.pkgbuild
    if pkgbuild is None:
        return []
    upstream = host_of(pkgbuild.url) if pkgbuild.url else None

    findings: list[Finding] = []
    for index, source in enumerate(pkgbuild.source):
        if is_vcs_source(source):
            continue
        url = source_url(source)
        host = host_of(url)
        scheme = url_scheme(url)
        if host is None or scheme is None:
            continue
        plain_http = scheme == "http"
        literal_ip = is_ip_host(host)
        if not (plain_http or literal_ip):
            continue

        trusted = upstream is not None and not literal_ip and same_domain(host, upstream)
        server = "plain HTTP" if plain_http else "a literal IP address"
        if plain_http and literal_ip:
            server = "plain HTTP and a literal IP address"
        severity = (
            Severity.LOW
            if trusted and aligned_strong_checksum(pkgbuild, index) is not None
            else Severity.MEDIUM
        )
        findings.append(
            finding(
                "R05",
                severity,
                f"source uses {server}",
                "PKGBUILD",
                line=_source_line(pkgbuild, source),
                snippet=source,
            )
        )
    return findings


@register("R06", Severity.LOW)
def r06_checksum_coverage(ctx: RuleContext) -> list[Finding]:
    """Flag ``SKIP`` checksums on non-VCS sources and source/checksum count mismatches.

    This rule emits at most one finding per file: the registry deduplicates by
    ``(rule_id, file, line)`` and both problems are reported on the same line.
    """
    pkgbuild = ctx.pkgbuild
    if pkgbuild is None or not pkgbuild.source:
        return []

    non_vcs_indices = [
        index for index, source in enumerate(pkgbuild.source) if not is_vcs_source(source)
    ]
    skipped = sum(
        1
        for _name, values in checksum_arrays(pkgbuild)
        for index in non_vcs_indices
        if index < len(values) and values[index].strip() == "SKIP"
    )
    mismatched = [
        name
        for name, values in checksum_arrays(pkgbuild)
        if values and len(values) != len(pkgbuild.source)
    ]

    problems: list[str] = []
    if skipped:
        problems.append(f"{skipped} checksum(s) are SKIP for non-VCS sources")
    if mismatched:
        problems.append(f"source/checksum count mismatch for {', '.join(mismatched)}")
    if not problems:
        return []

    line = line_of(pkgbuild.raw, "source=") or line_of(pkgbuild.raw, "sha256sums=")
    checksum = next((values[0] for _n, values in checksum_arrays(pkgbuild) if values), None)
    return [
        finding(
            "R06",
            Severity.LOW,
            "; ".join(problems),
            "PKGBUILD",
            line=line,
            snippet=checksum,
        )
    ]


def _source_line(pkgbuild: Pkgbuild, source: str) -> int | None:
    return line_of(pkgbuild.raw, source) or line_of(pkgbuild.raw, "source=")
