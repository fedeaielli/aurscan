"""Per-rule tests for R04-R06."""

from __future__ import annotations

from pathlib import Path

from aurscan.models import Severity
from aurscan.rules.common import same_domain
from tests.rules_utils import by_rule, run_rules

STRONG = "b1946ac92492d2347c6235b4d2611184b1946ac92492d2347c6235b4d2611184"
SOURCES_VAR_FIXTURE = Path(__file__).parent / "fixtures" / "suspicious" / "sources_var.PKGBUILD"


def test_r04_flags_foreign_and_user_content_hosts() -> None:
    source = f"""\
pkgname=demo
pkgver=1.0
pkgrel=1
arch=('x86_64')
url="https://example.invalid/demo"
source=(
  "https://mirror.invalid/demo.tar.gz"
  "https://raw.githubusercontent.com/user/repo/main/helper.sh"
  "https://cdn.example.invalid/demo.tar.gz"
  "local.patch"
)
sha256sums=('{STRONG}')
"""
    findings = by_rule(run_rules(source), "R04")

    assert len(findings) == 2
    assert all(finding.severity == Severity.MEDIUM for finding in findings)
    assert any("mirror.invalid" in finding.message for finding in findings)
    assert any("user-content" in finding.message for finding in findings)


def test_r04_checks_architecture_specific_sources() -> None:
    source = f"""\
pkgname=demo
pkgver=1.0
pkgrel=1
arch=('x86_64')
url="https://example.invalid/demo"
source_x86_64=("https://mirror.invalid/demo.tar.gz")
sha256sums_x86_64=('{STRONG}')
"""
    findings = by_rule(run_rules(source), "R04")

    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert "mirror.invalid" in findings[0].message


def test_r04_flags_source_built_from_variable_host() -> None:
    source = f"""\
pkgname=demo
pkgver=1.0
pkgrel=1
arch=('x86_64')
url="https://example.invalid/demo"
_mirror="https://mirror.invalid"
source=("$_mirror/demo-$pkgver.tar.gz")
sha256sums=('{STRONG}')
"""
    findings = by_rule(run_rules(source), "R04")

    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert "mirror.invalid" in findings[0].message
    # The finding carries the expanded URL that the rule inspected.
    assert findings[0].snippet == "https://mirror.invalid/demo-1.0.tar.gz"


def test_r04_skips_without_upstream_url_and_for_vcs_sources() -> None:
    source = f"""\
pkgname=demo
pkgver=1.0
pkgrel=1
arch=('x86_64')
source=("https://mirror.invalid/demo.tar.gz" "git+https://other.invalid/repo.git")
sha256sums=('{STRONG}')
"""
    findings = run_rules(source)
    assert by_rule(findings, "R04") == []


def test_r04_trusts_subdomain_of_upstream_domain() -> None:
    source = f"""\
pkgname=demo
pkgver=1.0
pkgrel=1
arch=('x86_64')
url="https://upstream.org/demo"
source=("https://dl1.upstream.org/file")
sha256sums=('{STRONG}')
"""
    assert by_rule(run_rules(source), "R04") == []


def test_r04_flags_unrelated_domain() -> None:
    source = f"""\
pkgname=demo
pkgver=1.0
pkgrel=1
arch=('x86_64')
url="https://upstream.org/demo"
source=("https://other.com/file")
sha256sums=('{STRONG}')
"""
    findings = by_rule(run_rules(source), "R04")

    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert "other.com" in findings[0].message


def test_same_domain_accepts_host_and_subdomains() -> None:
    assert same_domain("upstream.org", "upstream.org")
    assert same_domain("dl1.upstream.org", "upstream.org")
    assert not same_domain("other.com", "upstream.org")
    assert not same_domain("notupstream.org", "upstream.org")


def test_r05_http_is_medium_and_downgraded_with_trusted_checksum() -> None:
    source = f"""\
pkgname=demo
pkgver=1.0
pkgrel=1
arch=('x86_64')
url="https://example.invalid/demo"
source=(
  "http://example.invalid/demo.tar.gz"
  "http://mirror.invalid/demo.tar.gz"
  "https://192.0.2.10/demo.tar.gz"
)
sha256sums=('{STRONG}' '{STRONG}' '{STRONG}')
"""
    findings = by_rule(run_rules(source), "R05")

    severity_by_line = {finding.line: finding.severity for finding in findings}
    assert severity_by_line == {
        7: Severity.LOW,
        8: Severity.MEDIUM,
        9: Severity.MEDIUM,
    }


def test_r05_uses_architecture_specific_checksums() -> None:
    source = f"""\
pkgname=demo
pkgver=1.0
pkgrel=1
arch=('x86_64')
url="https://example.invalid/demo"
source_x86_64=("http://example.invalid/demo.tar.gz")
sha256sums_x86_64=('{STRONG}')
"""
    findings = by_rule(run_rules(source), "R05")

    assert len(findings) == 1
    assert findings[0].severity == Severity.LOW


def test_r05_flags_http_source_behind_variable() -> None:
    source = f"""\
pkgname=demo
pkgver=1.0
pkgrel=1
arch=('x86_64')
url="https://example.invalid/demo"
_plain="http://example.invalid"
source=("$_plain/demo-$pkgver.tar.gz")
sha256sums=('{STRONG}')
"""
    findings = by_rule(run_rules(source), "R05")

    assert len(findings) == 1
    assert findings[0].severity == Severity.LOW
    assert "plain HTTP" in findings[0].message


def test_r05_alignment_requires_matching_checksum_count() -> None:
    source = """\
pkgname=demo
pkgver=1.0
pkgrel=1
arch=('x86_64')
url="https://example.invalid/demo"
source=("http://example.invalid/demo.tar.gz")
sha256sums=('b1946ac92492d2347c6235b4d2611184b1946ac92492d2347c6235b4d2611184' 'extra')
"""
    findings = by_rule(run_rules(source), "R05")

    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


def test_r06_skip_and_mismatch_are_one_low_finding() -> None:
    source = """\
pkgname=demo
pkgver=1.0
pkgrel=1
arch=('x86_64')
source=("a.tar.gz" "b.tar.gz" "git+https://example.invalid/repo.git")
sha256sums=('SKIP' 'b1946ac92492d2347c6235b4d2611184')
"""
    findings = by_rule(run_rules(source), "R06")

    assert len(findings) == 1
    assert findings[0].severity == Severity.LOW
    assert "SKIP" in findings[0].message
    assert "mismatch" in findings[0].message


def test_r06_checks_architecture_specific_checksums() -> None:
    source = """\
pkgname=demo
pkgver=1.0
pkgrel=1
arch=('x86_64')
url="https://example.invalid/demo"
source_x86_64=("demo.tar.gz")
sha256sums_x86_64=('SKIP')
"""
    findings = by_rule(run_rules(source), "R06")

    assert len(findings) == 1
    assert findings[0].severity == Severity.LOW
    assert "SKIP" in findings[0].message
    assert findings[0].line == 6


def test_r06_skip_from_checksum_variable() -> None:
    source = """\
pkgname=demo
pkgver=1.0
pkgrel=1
arch=('x86_64')
_skip="SKIP"
source=("a.tar.gz")
sha256sums=("$_skip")
"""
    findings = by_rule(run_rules(source), "R06")

    assert len(findings) == 1
    assert findings[0].severity == Severity.LOW
    assert "SKIP" in findings[0].message


def test_r06_reports_architecture_checksum_mismatch_name() -> None:
    source = f"""\
pkgname=demo
pkgver=1.0
pkgrel=1
arch=('x86_64')
url="https://example.invalid/demo"
source_x86_64=("a.tar.gz" "b.tar.gz")
sha256sums_x86_64=('{STRONG}')
"""
    findings = by_rule(run_rules(source), "R06")

    assert len(findings) == 1
    assert "sha256sums_x86_64" in findings[0].message


def test_r06_skip_on_vcs_source_is_expected() -> None:
    source = """\
pkgname=demo
pkgver=1.0
pkgrel=1
arch=('x86_64')
source=("git+https://example.invalid/repo.git")
sha256sums=('SKIP')
"""
    assert by_rule(run_rules(source), "R06") == []


def test_r06_count_mismatch_without_skip() -> None:
    source = f"""\
pkgname=demo
pkgver=1.0
pkgrel=1
arch=('x86_64')
source=("a.tar.gz" "b.tar.gz")
sha256sums=('{STRONG}')
"""
    findings = by_rule(run_rules(source), "R06")

    assert len(findings) == 1
    assert findings[0].severity == Severity.LOW
    assert "mismatch" in findings[0].message
    assert "SKIP" not in findings[0].message


def test_r06_skip_without_count_mismatch() -> None:
    source = f"""\
pkgname=demo
pkgver=1.0
pkgrel=1
arch=('x86_64')
source=("a.tar.gz" "b.tar.gz")
sha256sums=('SKIP' '{STRONG}')
"""
    findings = by_rule(run_rules(source), "R06")

    assert len(findings) == 1
    assert findings[0].severity == Severity.LOW
    assert "SKIP" in findings[0].message
    assert "mismatch" not in findings[0].message


def test_r04_reports_each_arch_source_on_its_own_line() -> None:
    source = f"""\
pkgname=demo
pkgver=1.0
pkgrel=1
arch=('x86_64' 'aarch64')
url="https://example.invalid/demo"
_channel=stable
source_x86_64=("https://mirror.invalid/demo-${{_channel}}-amd64.tar.gz")
source_aarch64=("https://mirror.invalid/demo-${{_channel}}-arm64.tar.gz")
sha256sums_x86_64=('{STRONG}')
sha256sums_aarch64=('{STRONG}')
"""
    findings = by_rule(run_rules(source), "R04")

    assert [finding.line for finding in findings] == [7, 8]
    # Snippets keep the expanded form the rule inspected.
    assert sorted(finding.snippet or "" for finding in findings) == [
        "https://mirror.invalid/demo-stable-amd64.tar.gz",
        "https://mirror.invalid/demo-stable-arm64.tar.gz",
    ]


def test_r04_and_r05_lines_come_from_raw_entries() -> None:
    findings = run_rules(SOURCES_VAR_FIXTURE.read_text(encoding="utf-8"))

    assert [finding.line for finding in by_rule(findings, "R04")] == [10, 11, 19]
    assert [finding.line for finding in by_rule(findings, "R05")] == [11, 19]


def test_r04_still_dedupes_two_foreign_sources_on_one_line() -> None:
    source = f"""\
pkgname=demo
pkgver=1.0
pkgrel=1
arch=('x86_64')
url="https://example.invalid/demo"
source=("https://a.invalid/x.tar.gz" "https://b.invalid/y.tar.gz")
sha256sums=('{STRONG}' '{STRONG}')
"""
    findings = by_rule(run_rules(source), "R04")

    assert len(findings) == 1
    assert findings[0].line == 6
    assert "a.invalid" in findings[0].message
    assert "b.invalid" in findings[0].message
