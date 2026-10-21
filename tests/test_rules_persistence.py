"""Per-rule tests for R08."""

from __future__ import annotations

from aurscan.models import Severity
from tests.rules_utils import by_rule, run_rules


def test_r08_persistence_in_pkgbuild_is_high() -> None:
    source = """\
package() {
  systemctl enable demo.service
  echo "*/5 * * * * root /usr/bin/demo" >> /etc/cron.d/demo
  echo "demo" >> "$HOME/.bashrc"
  echo "x" >> /etc/ld.so.preload
  echo "[Desktop Entry]" >> "$HOME/.config/autostart/demo.desktop"
}
"""
    findings = by_rule(run_rules(source), "R08")

    assert len(findings) == 5
    assert all(finding.severity == Severity.HIGH for finding in findings)


def test_r08_systemctl_enable_in_install_hook_is_low() -> None:
    install = """\
post_install() {
  systemctl enable demo.service
}
"""
    findings = by_rule(run_rules(install_source=install), "R08")

    assert len(findings) == 1
    assert findings[0].severity == Severity.LOW
    assert findings[0].file == "test.install"


def test_r08_ignores_benign_commands() -> None:
    source = """\
package() {
  echo "hello" > "$pkgdir/usr/share/demo/message"
}
"""
    assert by_rule(run_rules(source), "R08") == []
