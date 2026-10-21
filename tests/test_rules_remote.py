"""Per-rule tests for R07."""

from __future__ import annotations

from aurscan.models import Severity
from tests.rules_utils import by_rule, run_rules


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
