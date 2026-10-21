"""M02-M04: package metadata rules.

M01 depends on git history and lives in :mod:`aurscan.history`.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import timedelta

from aurscan.models import Finding, Severity
from aurscan.rules import RuleContext, register, register_aggregate
from aurscan.rules.common import METADATA_FILE, finding

NEW_PACKAGE_DAYS = 30


@register("M02", Severity.LOW)
def m02_new_and_unvoted(ctx: RuleContext) -> list[Finding]:
    """Flag packages created less than 30 days ago that have no votes."""
    meta = ctx.meta
    if meta is None:
        return []
    age = ctx.now - meta.first_submitted
    if age >= timedelta(days=NEW_PACKAGE_DAYS) or meta.num_votes != 0:
        return []
    return [
        finding(
            "M02",
            Severity.LOW,
            "package was submitted less than 30 days ago and has no votes",
            METADATA_FILE,
            source="metadata",
        )
    ]


@register("M03", Severity.LOW)
def m03_out_of_date(ctx: RuleContext) -> list[Finding]:
    """Flag packages marked out of date by the maintainer or AUR users."""
    meta = ctx.meta
    if meta is None or meta.out_of_date is None:
        return []
    return [
        finding(
            "M03",
            Severity.LOW,
            "package is flagged out of date",
            METADATA_FILE,
            source="metadata",
        )
    ]


@register_aggregate("M04", Severity.LOW)
def m04_unpopular_high_risk(
    ctx: RuleContext, findings: Sequence[Finding]
) -> list[Finding]:
    """Flag zero-vote, zero-popularity packages that already have a high finding."""
    meta = ctx.meta
    if meta is None or meta.num_votes != 0 or meta.popularity != 0:
        return []
    if not any(
        existing.severity in {Severity.HIGH, Severity.CRITICAL} for existing in findings
    ):
        return []
    return [
        finding(
            "M04",
            Severity.LOW,
            "no votes and zero popularity despite high-severity findings",
            METADATA_FILE,
            source="metadata",
        )
    ]
