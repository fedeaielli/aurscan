"""Per-rule tests for R09-R10."""

from __future__ import annotations

from aurscan.models import Severity
from tests.rules_utils import by_rule, run_rules


def test_r09_setuid_is_high_and_setgid_is_low() -> None:
    source = """\
package() {
  chmod 4755 "$pkgdir/usr/bin/demo"
  chmod u+s "$pkgdir/usr/bin/helper"
  chmod 2755 "$pkgdir/usr/bin/group-helper"
  chmod 755 "$pkgdir/usr/bin/plain"
}
"""
    findings = by_rule(run_rules(source), "R09")

    assert len(findings) == 3
    assert [finding.severity for finding in findings] == [
        Severity.HIGH,
        Severity.HIGH,
        Severity.LOW,
    ]


def test_r10_flags_writes_outside_pkgdir_in_package_only() -> None:
    source = """\
build() {
  cp demo /usr/local/bin/demo
}

package() {
  cp demo /usr/local/bin/demo
  echo data > /etc/demo.conf
  tee /etc/demo.list < /dev/null
  cp demo relative/path
  cp demo "$pkgdir/usr/bin/demo"
  echo done > /dev/null
  cp demo "${pkgdir}/usr/bin/demo"
}
"""
    findings = by_rule(run_rules(source), "R10")

    assert len(findings) == 3
    assert all(finding.severity == Severity.MEDIUM for finding in findings)
    assert any("/usr/local/bin/demo" in finding.message for finding in findings)
    assert any("/etc/demo.conf" in finding.message for finding in findings)
    assert any("/etc/demo.list" in finding.message for finding in findings)


def test_r10_ignores_relative_destinations() -> None:
    source = """\
package() {
  install -d relative
  touch relative/file
}
"""
    assert by_rule(run_rules(source), "R10") == []
