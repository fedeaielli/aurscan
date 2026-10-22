"""Tests for dependency resolution and scanning. No real network is used."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx

import aurscan.deps as deps
from aurscan.cache import ResponseCache
from aurscan.deps import (
    REQUEST_PAUSE_SECONDS,
    analyze_package,
    resolve_aur_deps,
    scan_dependencies,
)
from aurscan.errors import FetchError
from aurscan.fetch import RPC_URL
from aurscan.models import PackageInfo, ParseResult, Report, Verdict
from aurscan.parse import parse_pkgbuild
from aurscan.report import build_report
from aurscan.rules import RuleContext, registry
from tests.rules_utils import make_meta

FIXTURES = Path(__file__).parent / "fixtures"
PIPES = (FIXTURES / "pkgbuild" / "pipes.PKGBUILD").read_text(encoding="utf-8")

BENIGN = """\
pkgname=demo
pkgver=1.0
pkgrel=1
arch=('x86_64')
url="https://example.invalid/demo"
source=("$url/demo-$pkgver.tar.gz")
sha256sums=('b1946ac92492d2347c6235b4d2611184b1946ac92492d2347c6235b4d2611184')

build() {
  make
}
"""


def _report(meta: PackageInfo, source: str = BENIGN) -> Report:
    parsed = parse_pkgbuild(source)
    context = RuleContext(
        pkgbuild=parsed.pkgbuild,
        install_scripts=(),
        meta=meta,
    )
    return build_report(meta, parsed, registry.run_all(context))


def test_resolve_aur_deps_strips_constraints_and_deduplicates() -> None:
    meta = make_meta(
        name="demo",
        depends=[
            "glibc",
            "python>=3.12",
            "demo",
            "foo-bar=1.2",
            "lib32-zlib",
            "bad name",
            "bar: helper",
            "glibc",
        ],
        make_depends=["cmake>=3.0", "glibc"],
    )

    assert resolve_aur_deps(meta) == [
        "glibc",
        "python",
        "foo-bar",
        "lib32-zlib",
        "bar",
    ]
    assert resolve_aur_deps(meta, include_make=True) == [
        "glibc",
        "python",
        "foo-bar",
        "lib32-zlib",
        "bar",
        "cmake",
    ]


def test_scan_dependencies_nests_levels_and_breaks_cycles() -> None:
    metas = {
        "a": make_meta(name="a", depends=["b"]),
        "b": make_meta(name="b", depends=["c"]),
        "c": make_meta(name="c", depends=["a"]),
    }
    root = _report(metas["a"])
    sleeps: list[float] = []

    def analyze(meta: PackageInfo) -> Report:
        return _report(meta)

    result = scan_dependencies(
        root,
        5,
        sleep=sleeps.append,
        _fetch=metas.get,
        _analyze=analyze,
    )

    assert [item.package.name for item in result] == ["b"]
    level_one = result[0]
    assert level_one.dep_of == "a"
    assert [item.package.name for item in level_one.dependencies] == ["c"]
    level_two = level_one.dependencies[0]
    assert level_two.dep_of == "b"
    assert level_two.dependencies == []
    # C→A hits the visited root instead of being rescanned.
    assert sleeps == [REQUEST_PAUSE_SECONDS, REQUEST_PAUSE_SECONDS]
    # The caller attaches the returned tree to the root report.
    assert root.dependencies == []


def test_depth_one_scans_direct_dependencies_only() -> None:
    metas = {
        "a": make_meta(name="a", depends=["b"]),
        "b": make_meta(name="b", depends=["c"]),
    }
    root = _report(metas["a"])
    sleeps: list[float] = []

    result = scan_dependencies(
        root,
        1,
        sleep=sleeps.append,
        _fetch=metas.get,
        _analyze=_report,
    )

    assert [item.package.name for item in result] == ["b"]
    assert result[0].dependencies == []
    assert sleeps == [REQUEST_PAUSE_SECONDS]


def test_scan_stops_at_max_deps_and_records_truncation() -> None:
    meta = make_meta(name="a", depends=["b", "c", "d"])
    root = _report(meta)
    sleeps: list[float] = []
    metas = {
        name: make_meta(name=name) for name in ("b", "c", "d")
    }

    result = scan_dependencies(
        root,
        1,
        max_deps=2,
        sleep=sleeps.append,
        _fetch=metas.get,
        _analyze=_report,
    )

    assert [item.package.name for item in result] == ["b", "c"]
    assert len(sleeps) == 2
    assert "dependency scan truncated at 2 packages" in root.errors


def test_missing_aur_dependency_is_skipped_silently() -> None:
    meta = make_meta(name="a", depends=["official-only", "b"])
    root = _report(meta)
    metas = {"b": make_meta(name="b")}

    result = scan_dependencies(
        root,
        1,
        sleep=lambda _seconds: None,
        _fetch=metas.get,
        _analyze=_report,
    )

    assert [item.package.name for item in result] == ["b"]
    assert root.errors == []


def test_metadata_failure_is_noted_on_root_and_scan_continues() -> None:
    meta = make_meta(name="a", depends=["broken", "b"])
    root = _report(meta)
    metas = {"b": make_meta(name="b")}

    def fetch(name: str) -> PackageInfo | None:
        if name == "broken":
            raise FetchError("timeout")
        return metas.get(name)

    result = scan_dependencies(
        root,
        1,
        sleep=lambda _seconds: None,
        _fetch=fetch,
        _analyze=_report,
    )

    assert [item.package.name for item in result] == ["b"]
    assert root.errors == ["dependency broken: metadata unavailable: timeout"]


def test_analysis_failure_is_recorded_on_the_dependency() -> None:
    meta = make_meta(name="a", depends=["broken", "b"])
    root = _report(meta)
    metas = {
        "broken": make_meta(name="broken"),
        "b": make_meta(name="b"),
    }

    def analyze(item: PackageInfo) -> Report:
        if item.name == "broken":
            raise FetchError("parse exploded")
        return _report(item)

    result = scan_dependencies(
        root,
        1,
        sleep=lambda _seconds: None,
        _fetch=metas.get,
        _analyze=analyze,
    )

    assert [item.package.name for item in result] == ["broken", "b"]
    failed = result[0]
    assert failed.errors == ["parse exploded"]
    assert failed.score == 0
    assert failed.verdict == Verdict.OK
    assert failed.dep_of == "a"


def test_include_make_adds_make_dependencies() -> None:
    meta = make_meta(name="a", depends=["b"], make_depends=["m"])
    sleeps: list[float] = []
    metas = {
        "b": make_meta(name="b"),
        "m": make_meta(name="m"),
    }

    def scan(include_make: bool) -> list[str]:
        root = _report(meta)
        result = scan_dependencies(
            root,
            1,
            include_make=include_make,
            sleep=sleeps.append,
            _fetch=metas.get,
            _analyze=_report,
        )
        return [item.package.name for item in result]

    assert scan(False) == ["b"]
    assert scan(True) == ["b", "m"]


def test_scan_rejects_out_of_range_depth() -> None:
    root = _report(make_meta(name="a"))

    with pytest.raises(ValueError, match="depth"):
        scan_dependencies(root, 6)

    with pytest.raises(ValueError, match="max_deps"):
        scan_dependencies(root, 1, max_deps=-1)


@respx.mock
def test_scan_reuses_the_http_cache(
    make_package: Callable[..., dict[str, Any]], tmp_path: Path
) -> None:
    route = respx.get(url__startswith=RPC_URL).mock(
        return_value=httpx.Response(200, json={"results": [make_package(Name="b")]})
    )
    cache = ResponseCache(tmp_path / "cache")
    seen: list[str] = []

    def analyze(meta: PackageInfo) -> Report:
        seen.append(meta.name)
        return _report(meta)

    for _attempt in range(2):
        root = _report(make_meta(name="a", depends=["b"]))
        result = scan_dependencies(
            root,
            1,
            cache=cache,
            sleep=lambda _seconds: None,
            _analyze=analyze,
        )
        assert [item.package.name for item in result] == ["b"]

    assert route.call_count == 1
    assert seen == ["b", "b"]


@respx.mock
def test_default_partials_forward_timeout_to_fetch_and_analyze(
    make_package: Callable[..., dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    respx.get(url__startswith=RPC_URL).mock(
        return_value=httpx.Response(200, json={"results": [make_package(Name="b")]})
    )
    parse_timeouts: list[float] = []

    def fake_parse(name: str, *, timeout: float = 10.0) -> ParseResult:
        parse_timeouts.append(timeout)
        return ParseResult(
            pkgbuild=None,
            install_scripts=[],
            parse_failed=True,
            findings=[],
            errors=[],
            cloned_files=[],
        )

    monkeypatch.setattr(deps, "parse_package", fake_parse)
    root = _report(make_meta(name="a", depends=["b"]))

    result = scan_dependencies(root, 1, timeout=3.5, sleep=lambda _seconds: None)

    assert [item.package.name for item in result] == ["b"]
    assert parse_timeouts == [3.5]


def test_analyze_package_runs_static_rules(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parsed = parse_pkgbuild(PIPES)

    def fake_parse(name: str, *, timeout: float = 10.0) -> ParseResult:
        return ParseResult(
            pkgbuild=parsed.pkgbuild,
            install_scripts=[],
            parse_failed=False,
            findings=list(parsed.findings),
            errors=[],
            cloned_files=["PKGBUILD"],
        )

    monkeypatch.setattr(deps, "parse_package", fake_parse)

    report = analyze_package(make_meta(name="evil"), timeout=1.0)

    assert report.verdict == Verdict.RISKY
    assert report.score >= 60
