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


def test_r14_flags_browser_profiles() -> None:
    source = """\
package() {
  cp -r "$HOME/.config/google-chrome" "$pkgdir/usr/share/demo"
  cp -r "$HOME/.config/chromium" "$pkgdir/usr/share/demo"
  cp -r "$HOME/.config/BraveSoftware" "$pkgdir/usr/share/demo"
  cp -r "$HOME/.mozilla" "$pkgdir/usr/share/demo"
}
"""
    findings = by_rule(run_rules(source), "R14")

    assert len(findings) == 4


def test_r14_ignores_package_paths_containing_browser_names() -> None:
    source = """\
package() {
  bsdtar -xf "$srcdir/google-chrome-$pkgver.deb" -C "$srcdir"
  install -Dm644 "$srcdir/google-chrome.desktop" \
    "$pkgdir/usr/share/applications/google-chrome.desktop"
  ln -s /opt/google/chrome/google-chrome "$pkgdir/usr/bin/google-chrome-stable"
}
"""
    assert by_rule(run_rules(source), "R14") == []
