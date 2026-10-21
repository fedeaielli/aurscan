"""Tests for the CLI, including exit-code remapping. No real network is used."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import httpx
import pytest
import respx

from aurscan.cli import main
from aurscan.fetch import RPC_URL


@pytest.fixture
def rpc_route(make_package: Callable[..., dict[str, Any]]) -> respx.Route:
    return respx.get(url__startswith=RPC_URL).mock(
        return_value=httpx.Response(200, json={"results": [make_package()]})
    )


@respx.mock
def test_human_output(
    rpc_route: respx.Route,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["demo"]) == 0
    out = capsys.readouterr().out
    assert "aurscan: demo" in out
    assert "version 1.2.3-1" in out
    assert "maintainer" in out
    assert rpc_route.called


@respx.mock
def test_orphaned_package_output(
    make_package: Callable[..., dict[str, Any]],
    capsys: pytest.CaptureFixture[str],
) -> None:
    respx.get(url__startswith=RPC_URL).mock(
        return_value=httpx.Response(200, json={"results": [make_package(Maintainer=None)]})
    )
    assert main(["demo"]) == 0
    assert "orphaned" in capsys.readouterr().out


@respx.mock
def test_json_output(
    rpc_route: respx.Route,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["demo", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["name"] == "demo"
    assert payload["version"] == "1.2.3-1"
    assert payload["first_submitted"].startswith("2023-11-14T22:13:20")


def test_invalid_name_exits_3(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["Demo"]) == 3
    captured = capsys.readouterr()
    assert "invalid AUR package name" in captured.err
    assert "\x1b" not in captured.err


def test_usage_error_exits_3_not_2(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--timeout", "0", "demo"]) == 3
    assert "Invalid value" in capsys.readouterr().err


def test_unknown_option_exits_3(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--nope", "demo"]) == 3
    assert "No such option" in capsys.readouterr().err


def test_help_exits_0(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--help"]) == 0
    assert "Usage" in capsys.readouterr().out


@respx.mock
def test_fetch_failure_exits_3(
    capsys: pytest.CaptureFixture[str],
) -> None:
    respx.get(url__startswith=RPC_URL).mock(return_value=httpx.Response(404))
    assert main(["demo"]) == 3
    captured = capsys.readouterr()
    assert "aurscan: error:" in captured.err
    assert "HTTP 404" in captured.err


@respx.mock
def test_fetch_failure_json_is_machine_readable(
    capsys: pytest.CaptureFixture[str],
) -> None:
    respx.get(url__startswith=RPC_URL).mock(return_value=httpx.Response(404))
    assert main(["demo", "--json"]) == 3
    payload = json.loads(capsys.readouterr().out)
    assert "HTTP 404" in payload["error"]


@respx.mock
def test_error_messages_are_sanitized(
    make_package: Callable[..., dict[str, Any]],
    capsys: pytest.CaptureFixture[str],
) -> None:
    respx.get(url__startswith=RPC_URL).mock(
        return_value=httpx.Response(
            200,
            json={"results": [make_package(Name="\x1b[31mdemo\x1b[0m")]},
        )
    )
    assert main(["demo"]) == 0
    assert "\x1b" not in capsys.readouterr().out
