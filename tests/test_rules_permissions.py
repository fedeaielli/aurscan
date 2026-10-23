"""Per-rule tests for R09-R10, R17."""

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


def test_r09_ignores_modes_that_remove_privilege_bits() -> None:
    source = """\
package() {
  chmod u-s "$pkgdir/usr/bin/a"
  chmod g-s "$pkgdir/usr/bin/b"
  chmod a-s "$pkgdir/usr/bin/c"
  chmod ug-s "$pkgdir/usr/bin/d"
  chmod -R u-s "$pkgdir/usr/share/code"
}
"""
    assert by_rule(run_rules(source), "R09") == []


def test_r09_applies_symbolic_clauses_in_order() -> None:
    source = """\
package() {
  chmod u+s,u-s "$pkgdir/usr/bin/never"
  chmod u-s,u+s "$pkgdir/usr/bin/final"
  chmod u+s,g-s "$pkgdir/usr/bin/only-user"
  chmod u=rwxs "$pkgdir/usr/bin/exact"
  chmod u=rwx "$pkgdir/usr/bin/cleared"
}
"""
    findings = by_rule(run_rules(source), "R09")

    assert [(finding.line, finding.severity) for finding in findings] == [
        (3, Severity.HIGH),
        (4, Severity.HIGH),
        (5, Severity.HIGH),
    ]


def test_r09_ignores_targets_without_privilege_bits() -> None:
    source = """\
package() {
  chmod o+s "$pkgdir/usr/bin/others"
  chmod +s "$pkgdir/usr/bin/everyone"
}
"""
    findings = by_rule(run_rules(source), "R09")

    assert [(finding.line, finding.severity) for finding in findings] == [
        (3, Severity.HIGH)
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


def test_r17_setuid_install_modes_are_high_and_setgid_is_low() -> None:
    source = """\
package() {
  install -m 4755 demo "$pkgdir/usr/bin/setuid"
  install -m4755 demo "$pkgdir/usr/bin/attached"
  install -m u+s demo "$pkgdir/usr/bin/symbolic"
  install --mode=u+s demo "$pkgdir/usr/bin/long-option"
  install -D -m 6755 -o root demo "$pkgdir/usr/bin/both"
  install -m 2755 demo "$pkgdir/usr/bin/group"
  install -m g+s demo "$pkgdir/usr/bin/group-symbolic"
}
"""
    findings = by_rule(run_rules(source), "R17")

    assert [(finding.line, finding.severity) for finding in findings] == [
        (2, Severity.HIGH),
        (3, Severity.HIGH),
        (4, Severity.HIGH),
        (5, Severity.HIGH),
        (6, Severity.HIGH),
        (7, Severity.LOW),
        (8, Severity.LOW),
    ]
    assert all("install -m" in finding.message for finding in findings)


def test_r17_ignores_plain_and_bit_removing_modes() -> None:
    source = """\
package() {
  install -Dm755 demo "$pkgdir/usr/bin/demo"
  install -Dm0644 doc "$pkgdir/usr/share/doc/doc"
  install -m 0755 demo "$pkgdir/usr/bin/padded"
  install -m 00755 demo "$pkgdir/usr/bin/padded-more"
  install -m 755 demo "$pkgdir/usr/bin/plain"
  install -m 644 demo "$pkgdir/usr/bin/file"
  install -d -m 755 "$pkgdir/usr/share/data"
  install -m u-s demo "$pkgdir/usr/bin/removed"
  install -m u=rwx demo "$pkgdir/usr/bin/exact"
  install demo "$pkgdir/usr/bin/no-mode"
}
"""
    assert by_rule(run_rules(source), "R17") == []


def test_r17_only_runs_inside_build_and_package_functions() -> None:
    source = """\
prepare() {
  install -m 4755 demo "$pkgdir/usr/bin/prepare"
}

build() {
  install -m 4755 demo "$pkgdir/usr/bin/build"
}

package_extra() {
  install -m 4755 demo "$pkgdir/usr/bin/extra"
}

_helper() {
  install -m 4755 demo /tmp/helper
}

check() {
  install -m 4755 demo /tmp/check
}
"""
    findings = by_rule(run_rules(source), "R17")

    assert len(findings) == 3
    assert sorted(finding.message for finding in findings) == [
        "install -m sets the setuid bit in build()",
        "install -m sets the setuid bit in package_extra()",
        "install -m sets the setuid bit in prepare()",
    ]


def test_r17_does_not_guess_unresolved_modes() -> None:
    source = """\
package() {
  install -m "$mode" demo "$pkgdir/usr/bin/from-variable"
  install -m "$(printf 4755)" demo "$pkgdir/usr/bin/from-substitution"
  install -Dm demo "$pkgdir/usr/bin/from-flag-bundle"
}
"""
    assert by_rule(run_rules(source), "R17") == []
