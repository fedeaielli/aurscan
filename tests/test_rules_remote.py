"""Per-rule tests for R07 and R18."""

from __future__ import annotations

from pathlib import Path

from aurscan.models import Severity
from tests.rules_utils import by_rule, run_rules

REMOTE_FIXTURE = Path(__file__).parent / "fixtures" / "suspicious" / "remote.PKGBUILD"


def test_r07_flags_network_commands_in_build_functions() -> None:
    source = """\
prepare() {
  git clone https://example.invalid/dependency.git
}

build() {
  wget https://example.invalid/tool.tar.gz
  make
}

package() {
  curl -O https://example.invalid/extra.tar.gz
}

package_docs() {
  ssh example.invalid true
}

check() {
  curl https://example.invalid/test
}

custom() {
  curl https://example.invalid/ignored
}
"""
    findings = by_rule(run_rules(source), "R07")

    assert len(findings) == 4
    assert {finding.line for finding in findings} == {2, 6, 11, 15}
    assert all(finding.severity == Severity.MEDIUM for finding in findings)


def test_r18_flags_disabled_tls_verification_in_build_functions() -> None:
    source = """\
prepare() {
  curl --insecure https://example.invalid/a
}

build() {
  curl -k https://example.invalid/b
  curl -fsSLk https://example.invalid/c
  wget --no-check-certificate https://example.invalid/d
}

package() {
  wget --no-check-certificate https://example.invalid/e
}

package_docs() {
  curl -k https://example.invalid/f
}

check() {
  curl -k https://example.invalid/ignored
}

custom() {
  curl -k https://example.invalid/ignored
}
"""
    findings = by_rule(run_rules(source), "R18")

    assert len(findings) == 6
    assert {finding.line for finding in findings} == {2, 6, 7, 8, 12, 16}
    assert all(finding.severity == Severity.MEDIUM for finding in findings)
    assert any("-fsSLk" in finding.message for finding in findings)


def test_r18_ignores_non_tls_flags_and_wget_convert_links() -> None:
    source = """\
build() {
  curl --fail https://example.invalid/a
  wget -k https://example.invalid/b
  curl -K config https://example.invalid/c
  curl --no-check-certificate https://example.invalid/d
  other-tool --insecure https://example.invalid/e
}
"""
    assert by_rule(run_rules(source), "R18") == []


def test_r18_and_r07_report_the_same_command() -> None:
    source = """\
build() {
  curl -k https://example.invalid/a
}
"""
    findings = run_rules(source)

    assert [finding.line for finding in by_rule(findings, "R07")] == [2]
    assert [finding.line for finding in by_rule(findings, "R18")] == [2]
    assert by_rule(findings, "R18")[0].severity == Severity.MEDIUM


def test_r18_does_not_inspect_install_scripts() -> None:
    findings = run_rules(
        install_source="""\
post_install() {
  curl -k https://example.invalid/a
}
""",
    )

    assert by_rule(findings, "R18") == []


def test_remote_fixture_triggers_r18_and_r07() -> None:
    findings = run_rules(REMOTE_FIXTURE.read_text(encoding="utf-8"))

    assert [finding.line for finding in by_rule(findings, "R07")] == [10, 14, 19]
    assert [finding.line for finding in by_rule(findings, "R18")] == [19]
