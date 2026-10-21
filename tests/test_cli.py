"""Tests for the CLI, including verdict exit codes and cache handling."""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx

import aurscan.cli as cli
from aurscan.errors import HistoryError
from aurscan.fetch import RPC_URL
from aurscan.history import Commit
from aurscan.models import ParseResult, Report
from aurscan.parse import parse_install_script, parse_pkgbuild
from aurscan.report import build_report
from aurscan.rules import RuleContext, registry
from tests.rules_utils import make_meta

FIXTURES = Path(__file__).parent / "fixtures"

BENIGN = (FIXTURES / "benign" / "PKGBUILD").read_text(encoding="utf-8")
PIPES = (FIXTURES / "pkgbuild" / "pipes.PKGBUILD").read_text(encoding="utf-8")
REVIEW_PKGBUILD = """\
pkgname=demo
pkgver=1.0
pkgrel=1
arch=('x86_64')
url="https://example.invalid/demo"

build() {
  curl -s https://example.invalid/x.sh | sh
}
"""


def _parse_result(
    source: str,
    *,
    install: str | None = None,
    cloned_files: list[str] | None = None,
    errors: list[str] | None = None,
) -> ParseResult:
    parsed = parse_pkgbuild(source)
    install_scripts = []
    if install is not None:
        install_scripts = parse_install_script(install, "demo.install").install_scripts
    return ParseResult(
        pkgbuild=parsed.pkgbuild,
        install_scripts=install_scripts,
        parse_failed=parsed.parse_failed,
        findings=list(parsed.findings),
        errors=list(errors or []),
        cloned_files=list(cloned_files if cloned_files is not None else ["PKGBUILD"]),
    )


@pytest.fixture
def set_parse(monkeypatch: pytest.MonkeyPatch) -> Callable[[ParseResult], None]:
    """Replace the clone/parse step with a prepared result."""

    def _set(result: ParseResult) -> None:
        def fake(name: str, *, timeout: float = 30.0) -> ParseResult:
            return result

        monkeypatch.setattr(cli, "parse_package", fake)
        # Keep the history clone off by default; individual tests override it.
        monkeypatch.setattr(cli, "clone_history", lambda _name: [])

    return _set


@pytest.fixture
def rpc_route(make_package: Callable[..., dict[str, Any]]) -> respx.Route:
    return respx.get(url__startswith=RPC_URL).mock(
        return_value=httpx.Response(200, json={"results": [make_package()]})
    )


@respx.mock
def test_human_output(
    rpc_route: respx.Route,
    set_parse: Callable[[ParseResult], None],
    capsys: pytest.CaptureFixture[str],
) -> None:
    set_parse(_parse_result(BENIGN))

    assert cli.main(["demo"]) == 0
    out = capsys.readouterr().out
    assert "aurscan: demo" in out
    assert "version 1.2.3-1" in out
    assert "Risk: OK" in out
    assert "maintainer" in out
    assert rpc_route.called


@respx.mock
def test_orphaned_package_output(
    make_package: Callable[..., dict[str, Any]],
    set_parse: Callable[[ParseResult], None],
    capsys: pytest.CaptureFixture[str],
) -> None:
    respx.get(url__startswith=RPC_URL).mock(
        return_value=httpx.Response(200, json={"results": [make_package(Maintainer=None)]})
    )
    set_parse(_parse_result(BENIGN))

    assert cli.main(["demo"]) == 0
    assert "orphaned" in capsys.readouterr().out


@respx.mock
def test_json_output_is_a_full_report(
    rpc_route: respx.Route,
    set_parse: Callable[[ParseResult], None],
    capsys: pytest.CaptureFixture[str],
) -> None:
    set_parse(_parse_result(BENIGN))

    assert cli.main(["demo", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["package"]["name"] == "demo"
    assert payload["package"]["version"] == "1.2.3-1"
    assert payload["package"]["first_submitted"].startswith("2023-11-14T22:13:20")
    assert payload["verdict"] == "ok"
    assert payload["score"] == 0
    assert payload["findings"] == []
    assert payload["dependencies"] == []


@respx.mock
def test_review_verdict_exits_1(
    rpc_route: respx.Route,
    set_parse: Callable[[ParseResult], None],
    capsys: pytest.CaptureFixture[str],
) -> None:
    set_parse(_parse_result(REVIEW_PKGBUILD))

    assert cli.main(["demo"]) == 1
    out = capsys.readouterr().out
    assert "Risk: REVIEW" in out
    assert "R01" in out


@respx.mock
def test_high_findings_exit_2(
    rpc_route: respx.Route,
    set_parse: Callable[[ParseResult], None],
    capsys: pytest.CaptureFixture[str],
) -> None:
    set_parse(_parse_result(PIPES))

    assert cli.main(["demo"]) == 2
    out = capsys.readouterr().out
    assert "Risk: RISKY" in out
    assert "R01" in out
    assert "[HIGH]" in out


@respx.mock
def test_analysis_errors_are_surfaced_without_crashing(
    rpc_route: respx.Route,
    set_parse: Callable[[ParseResult], None],
    capsys: pytest.CaptureFixture[str],
) -> None:
    set_parse(_parse_result(BENIGN, errors=["could not clone demo: timeout"]))

    assert cli.main(["demo"]) == 0
    out = capsys.readouterr().out
    assert "Analysis notes" in out
    assert "could not clone demo: timeout" in out


@respx.mock
def test_clone_failure_json_contains_errors(
    rpc_route: respx.Route,
    set_parse: Callable[[ParseResult], None],
    capsys: pytest.CaptureFixture[str],
) -> None:
    failed = ParseResult(
        pkgbuild=None,
        install_scripts=[],
        parse_failed=True,
        errors=["could not clone demo: timeout"],
    )
    set_parse(failed)

    # Exit 0 is intentional: a clone failure is an analysis error, not an
    # operational failure. Per hard-rule 8 the scan continues with metadata only.
    assert cli.main(["demo", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["package"]["name"] == "demo"
    assert payload["errors"] == ["could not clone demo: timeout"]


def test_invalid_name_exits_3(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["Demo"]) == 3
    captured = capsys.readouterr()
    assert "invalid AUR package name" in captured.err
    assert "\x1b" not in captured.err


def test_usage_error_exits_3_not_2(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["--timeout", "0", "demo"]) == 3
    assert "Invalid value" in capsys.readouterr().err


def test_unknown_option_exits_3(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["--nope", "demo"]) == 3
    assert "No such option" in capsys.readouterr().err


def test_help_exits_0(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["--help"]) == 0
    assert "Usage" in capsys.readouterr().out


@respx.mock
def test_fetch_failure_exits_3(capsys: pytest.CaptureFixture[str]) -> None:
    respx.get(url__startswith=RPC_URL).mock(return_value=httpx.Response(404))
    assert cli.main(["demo"]) == 3
    captured = capsys.readouterr()
    assert "aurscan: error:" in captured.err
    assert "HTTP 404" in captured.err


@respx.mock
def test_fetch_failure_json_is_machine_readable(
    capsys: pytest.CaptureFixture[str],
) -> None:
    respx.get(url__startswith=RPC_URL).mock(return_value=httpx.Response(404))
    assert cli.main(["demo", "--json"]) == 3
    payload = json.loads(capsys.readouterr().out)
    assert "HTTP 404" in payload["error"]


@respx.mock
def test_error_messages_are_sanitized(
    make_package: Callable[..., dict[str, Any]],
    set_parse: Callable[[ParseResult], None],
    capsys: pytest.CaptureFixture[str],
) -> None:
    respx.get(url__startswith=RPC_URL).mock(
        return_value=httpx.Response(
            200,
            json={"results": [make_package(Name="\x1b[31mdemo\x1b[0m")]},
        )
    )
    set_parse(_parse_result(BENIGN))

    assert cli.main(["demo"]) == 0
    assert "\x1b" not in capsys.readouterr().out


@respx.mock
def test_no_cache_writes_nothing(
    rpc_route: respx.Route,
    set_parse: Callable[[ParseResult], None],
    tmp_path: Path,
) -> None:
    set_parse(_parse_result(BENIGN))

    assert cli.main(["demo", "--no-cache"]) == 0
    assert not (tmp_path / "cache-home" / "aurscan").exists()


@respx.mock
def test_cache_reuses_a_response(
    rpc_route: respx.Route,
    set_parse: Callable[[ParseResult], None],
) -> None:
    set_parse(_parse_result(BENIGN))

    assert cli.main(["demo"]) == 0
    assert cli.main(["demo"]) == 0
    assert rpc_route.call_count == 1


@respx.mock
def test_history_findings_are_reported(
    rpc_route: respx.Route,
    set_parse: Callable[[ParseResult], None],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    set_parse(_parse_result(BENIGN))
    commit = Commit(
        hash="a" * 40,
        author="Bob",
        date=datetime(2026, 1, 1, tzinfo=UTC),
        message="add update step",
        files=["PKGBUILD"],
        added_lines={"PKGBUILD": [8]},
        content={"PKGBUILD": REVIEW_PKGBUILD},
        tree_files=["PKGBUILD"],
    )
    monkeypatch.setattr(cli, "clone_history", lambda _name: [commit])

    assert cli.main(["demo"]) == 1
    out = capsys.readouterr().out
    assert "R01" in out
    assert "new in commit aaaaaaa:" in out


@respx.mock
def test_no_history_skips_the_history_clone(
    rpc_route: respx.Route,
    set_parse: Callable[[ParseResult], None],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    set_parse(_parse_result(BENIGN))

    def _unexpected(_name: str) -> list[Commit]:
        raise AssertionError("history must not run with --no-history")

    monkeypatch.setattr(cli, "clone_history", _unexpected)

    assert cli.main(["demo", "--no-history"]) == 0


@respx.mock
def test_history_failure_is_an_analysis_note(
    rpc_route: respx.Route,
    set_parse: Callable[[ParseResult], None],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    set_parse(_parse_result(BENIGN))

    def _fail(_name: str) -> list[Commit]:
        raise HistoryError("git log failed")

    monkeypatch.setattr(cli, "clone_history", _fail)

    assert cli.main(["demo"]) == 0
    out = capsys.readouterr().out
    assert "Analysis notes" in out
    assert "history analysis failed: git log failed" in out


def _dep_report(name: str, source: str, parent: str) -> Report:
    meta = make_meta(name=name)
    parsed = parse_pkgbuild(source)
    context = RuleContext(
        pkgbuild=parsed.pkgbuild,
        install_scripts=(),
        meta=meta,
    )
    report = build_report(meta, parsed, registry.run_all(context))
    return report.model_copy(update={"dep_of": parent})


@respx.mock
def test_dependency_risk_sets_the_exit_code(
    rpc_route: respx.Route,
    set_parse: Callable[[ParseResult], None],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    set_parse(_parse_result(BENIGN))
    dependency = _dep_report("evil", PIPES, parent="demo")

    def fake_scan(
        _root: Report, _depth: int, **_kwargs: object
    ) -> list[Report]:
        return [dependency]

    monkeypatch.setattr(cli, "scan_dependencies", fake_scan)

    # The root stays OK; the risky dependency drives the exit code.
    assert cli.main(["demo", "--deps"]) == 2
    out = capsys.readouterr().out
    assert "Risk: OK" in out
    assert "Dependencies" in out
    assert "evil" in out
    assert "Highest dependency risk: evil (100)" in out


@respx.mock
def test_json_dependencies_are_nested(
    rpc_route: respx.Route,
    set_parse: Callable[[ParseResult], None],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    set_parse(_parse_result(BENIGN))
    dependency = _dep_report("lib", BENIGN, parent="demo")
    dependency.dependencies.append(_dep_report("evil", PIPES, parent="lib"))

    def fake_scan(
        _root: Report, _depth: int, **_kwargs: object
    ) -> list[Report]:
        return [dependency]

    monkeypatch.setattr(cli, "scan_dependencies", fake_scan)

    assert cli.main(["demo", "--deps", "--depth", "2", "--json"]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["score"] == 0
    assert payload["verdict"] == "ok"
    assert payload["dependencies"][0]["package"]["name"] == "lib"
    assert payload["dependencies"][0]["dep_of"] == "demo"
    assert payload["dependencies"][0]["dependencies"][0]["package"]["name"] == "evil"
    assert payload["dependencies"][0]["dependencies"][0]["dep_of"] == "lib"


@respx.mock
def test_dependency_options_are_forwarded(
    rpc_route: respx.Route,
    set_parse: Callable[[ParseResult], None],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    set_parse(_parse_result(BENIGN))
    captured: dict[str, object] = {}

    def fake_scan(
        _root: Report, depth: int, **kwargs: object
    ) -> list[Report]:
        captured["depth"] = depth
        captured.update(kwargs)
        return []

    monkeypatch.setattr(cli, "scan_dependencies", fake_scan)

    assert (
        cli.main(
            [
                "demo",
                "--deps",
                "--depth",
                "3",
                "--include-make",
                "--max-deps",
                "7",
            ]
        )
        == 0
    )
    assert captured["depth"] == 3
    assert captured["include_make"] is True
    assert captured["max_deps"] == 7
    assert captured["timeout"] == 10.0


@respx.mock
def test_without_deps_flag_dependencies_are_not_scanned(
    rpc_route: respx.Route,
    set_parse: Callable[[ParseResult], None],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    set_parse(_parse_result(BENIGN))

    def unexpected(*_args: object, **_kwargs: object) -> list[Report]:
        raise AssertionError("dependencies must not be scanned without --deps")

    monkeypatch.setattr(cli, "scan_dependencies", unexpected)

    assert cli.main(["demo"]) == 0


def test_dependency_depth_above_max_is_a_usage_error(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert cli.main(["demo", "--deps", "--depth", "6"]) == 3
    assert "Invalid value" in capsys.readouterr().err


@respx.mock
def test_dependency_errors_are_rendered(
    rpc_route: respx.Route,
    set_parse: Callable[[ParseResult], None],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    set_parse(_parse_result(BENIGN))
    dependency = _dep_report("broken", BENIGN, parent="demo").model_copy(
        update={"errors": ["could not clone broken: timeout"]}
    )

    def fake_scan(
        _root: Report, _depth: int, **_kwargs: object
    ) -> list[Report]:
        return [dependency]

    monkeypatch.setattr(cli, "scan_dependencies", fake_scan)

    assert cli.main(["demo", "--deps"]) == 0
    out = capsys.readouterr().out
    assert "Dependency notes" in out
    assert "broken: could not clone broken: timeout" in out

