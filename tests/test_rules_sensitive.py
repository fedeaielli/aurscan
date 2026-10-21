"""Per-rule tests for R14."""

from __future__ import annotations

from aurscan.models import Severity
from tests.rules_utils import by_rule, run_rules


def test_r14_flags_credentials_and_wallets() -> None:
    source = """\
package() {
  cp -r "$HOME/.ssh" "$pkgdir/usr/share/demo/ssh"
  cp -r "$HOME/.gnupg" "$pkgdir/usr/share/demo/gnupg"
  cp "$HOME/.aws/credentials" "$pkgdir/usr/share/demo/credentials"
  cp "$HOME/.bitcoin/wallet.dat" "$pkgdir/usr/share/demo/wallet.dat"
}
"""
    findings = by_rule(run_rules(source), "R14")

    assert len(findings) == 4
    assert all(finding.severity == Severity.HIGH for finding in findings)


def test_r14_ignores_regular_paths() -> None:
    source = """\
package() {
  install -Dm644 README.md "$pkgdir/usr/share/demo/README.md"
}
"""
    assert by_rule(run_rules(source), "R14") == []
