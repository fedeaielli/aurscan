"""Per-rule tests for R12."""

from __future__ import annotations

from aurscan.models import Severity
from tests.rules_utils import by_rule, run_rules

BLOB = (
    "odJFCrnl2edlBDdz1C5Jau2RJtBRnlWmTSHf6pWkLUyifDLkDmWJ6UuVTAIjvFu7WICPhDeOZIiBOB"
    "/Y6sHrFH2ZUCr/lgotu2iXW7GboIRoL3u6aHwnMztVuaP+coUNEhEkk+iqq8vH2BzNZV45pFCiRc"
    "DCajhDieQjEJ+Bq8F80ymm3T207gmhZRnFyy5r2xJ7Fj4mgblEv0+9BZhvWaXH6K2+tyLBhhOhg9u"
    "hkxiiEZpF"
)


def test_r12_flags_high_entropy_string() -> None:
    source = f'prepare() {{\n  blob="{BLOB}"\n}}\n'
    findings = by_rule(run_rules(source), "R12")

    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert "high-entropy" in findings[0].message


def test_r12_ignores_long_strings_with_whitespace_or_low_entropy() -> None:
    sentence = " ".join(["word"] * 80)
    padding = "a" * 250
    source = f'prepare() {{\n  text="{sentence}"\n  padding="{padding}"\n}}\n'
    assert by_rule(run_rules(source), "R12") == []


def test_r12_flags_escape_run_and_printf_escapes() -> None:
    escapes = "".join(f"\\x{value:02x}" for value in range(0x41, 0x4A))
    source = f"""\
prepare() {{
  payload="{escapes}"
  printf '\\x41\\x42\\x43\\x44\\x45\\x46\\x47\\x48\\x49' > payload.bin
}}
"""
    findings = by_rule(run_rules(source), "R12")

    assert len(findings) == 2
    assert {finding.line for finding in findings} == {2, 3}


def test_r12_ignores_comment_strings() -> None:
    source = f'prepare() {{\n  # blob="{BLOB}"\n}}\n'
    assert by_rule(run_rules(source), "R12") == []
