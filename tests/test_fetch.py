"""Tests for AUR RPC fetching. No real network is used."""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import UTC, datetime
from email.utils import formatdate
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx

from aurscan.cache import ResponseCache
from aurscan.errors import FetchError, InvalidPackageNameError
from aurscan.fetch import (
    BATCH_SIZE,
    MAX_BODY_BYTES,
    RPC_URL,
    USER_AGENT,
    fetch_meta,
    fetch_meta_many,
)

from .conftest import BASE_EPOCH


@respx.mock
def test_fetch_meta_maps_fields(make_package: Callable[..., dict[str, Any]]) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["user-agent"] == USER_AGENT
        assert request.url.params.get_list("arg[]") == ["demo"]
        return httpx.Response(200, json={"results": [make_package()]})

    route = respx.get(url__startswith=RPC_URL).mock(side_effect=handler)
    info = fetch_meta("demo")

    assert route.called
    assert info.name == "demo"
    assert info.version == "1.2.3-1"
    assert info.maintainer == "maintainer"
    assert info.num_votes == 42
    assert info.first_submitted == datetime.fromtimestamp(BASE_EPOCH, tz=UTC)
    assert info.depends == ["glibc"]
    assert info.make_depends == ["gcc"]
    assert info.opt_depends == ["bash: for scripts"]


@respx.mock
def test_fetch_meta_orphaned_and_empty_url(make_package: Callable[..., dict[str, Any]]) -> None:
    payload = make_package(Maintainer=None, Submitter="", URL="")
    respx.get(url__startswith=RPC_URL).mock(
        return_value=httpx.Response(200, json={"results": [payload]})
    )

    info = fetch_meta("demo")
    assert info.maintainer is None
    assert info.submitter is None
    assert info.url is None


@respx.mock
def test_fetch_meta_not_found() -> None:
    respx.get(url__startswith=RPC_URL).mock(
        return_value=httpx.Response(200, json={"results": []})
    )
    with pytest.raises(FetchError, match="not found"):
        fetch_meta("demo")


@respx.mock
def test_fetch_meta_invalid_name_makes_no_request() -> None:
    route = respx.get(url__startswith=RPC_URL).mock(return_value=httpx.Response(200))
    with pytest.raises(InvalidPackageNameError):
        fetch_meta("Demo")
    assert not route.called


@respx.mock
def test_fetch_meta_invalid_json() -> None:
    respx.get(url__startswith=RPC_URL).mock(
        return_value=httpx.Response(200, content=b"not json")
    )
    with pytest.raises(FetchError, match="invalid JSON"):
        fetch_meta("demo")


@respx.mock
def test_fetch_meta_malformed_result(make_package: Callable[..., dict[str, Any]]) -> None:
    payload = make_package()
    del payload["URL"]
    payload["URL"] = 123
    respx.get(url__startswith=RPC_URL).mock(
        return_value=httpx.Response(200, json={"results": [payload]})
    )
    with pytest.raises(FetchError, match="invalid URL"):
        fetch_meta("demo")


@respx.mock
def test_fetch_meta_retries_transient_errors(
    make_package: Callable[..., dict[str, Any]],
) -> None:
    route = respx.get(url__startswith=RPC_URL).mock(
        side_effect=[
            httpx.Response(503),
            httpx.Response(429),
            httpx.Response(500),
            httpx.Response(200, json={"results": [make_package()]}),
        ]
    )
    sleeps: list[float] = []

    info = fetch_meta("demo", sleep=sleeps.append)

    assert info.name == "demo"
    assert route.call_count == 4
    assert len(sleeps) == 3


@respx.mock
def test_fetch_meta_honours_retry_after_seconds(
    make_package: Callable[..., dict[str, Any]],
) -> None:
    route = respx.get(url__startswith=RPC_URL).mock(
        side_effect=[
            httpx.Response(429, headers={"Retry-After": "5"}),
            httpx.Response(200, json={"results": [make_package()]}),
        ]
    )
    sleeps: list[float] = []

    info = fetch_meta("demo", sleep=sleeps.append)

    assert info.name == "demo"
    assert route.call_count == 2
    assert sleeps == [5.0]


@respx.mock
def test_fetch_meta_honours_retry_after_http_date(
    make_package: Callable[..., dict[str, Any]],
) -> None:
    retry_at = formatdate(time.time() + 30, usegmt=True)
    respx.get(url__startswith=RPC_URL).mock(
        side_effect=[
            httpx.Response(429, headers={"Retry-After": retry_at}),
            httpx.Response(200, json={"results": [make_package()]}),
        ]
    )
    sleeps: list[float] = []

    fetch_meta("demo", sleep=sleeps.append)

    assert len(sleeps) == 1
    assert sleeps[0] == pytest.approx(30.0, abs=2.0)


@respx.mock
def test_fetch_meta_invalid_retry_after_falls_back_to_backoff(
    make_package: Callable[..., dict[str, Any]],
) -> None:
    respx.get(url__startswith=RPC_URL).mock(
        side_effect=[
            httpx.Response(429, headers={"Retry-After": "not-a-date"}),
            httpx.Response(200, json={"results": [make_package()]}),
        ]
    )
    sleeps: list[float] = []

    fetch_meta("demo", sleep=sleeps.append)

    assert len(sleeps) == 1
    assert 0.5 <= sleeps[0] <= 0.75


@respx.mock
def test_fetch_meta_caps_retry_after(
    make_package: Callable[..., dict[str, Any]],
) -> None:
    respx.get(url__startswith=RPC_URL).mock(
        side_effect=[
            httpx.Response(429, headers={"Retry-After": "100000"}),
            httpx.Response(200, json={"results": [make_package()]}),
        ]
    )
    sleeps: list[float] = []

    fetch_meta("demo", sleep=sleeps.append)

    assert sleeps == [120.0]


@respx.mock
def test_fetch_meta_gives_up_after_retries() -> None:
    route = respx.get(url__startswith=RPC_URL).mock(return_value=httpx.Response(503))
    with pytest.raises(FetchError, match="failed after 4 attempts"):
        fetch_meta("demo", sleep=lambda _: None)
    assert route.call_count == 4


@respx.mock
def test_fetch_meta_does_not_retry_client_errors() -> None:
    route = respx.get(url__startswith=RPC_URL).mock(return_value=httpx.Response(404))
    with pytest.raises(FetchError, match="HTTP 404"):
        fetch_meta("demo", sleep=lambda _: None)
    assert route.call_count == 1


@respx.mock
def test_fetch_meta_rejects_oversized_body() -> None:
    respx.get(url__startswith=RPC_URL).mock(
        return_value=httpx.Response(200, content=b"x" * (MAX_BODY_BYTES + 1))
    )
    with pytest.raises(FetchError, match="exceeds"):
        fetch_meta("demo")


@respx.mock
def test_fetch_meta_retries_network_errors(
    make_package: Callable[..., dict[str, Any]],
) -> None:
    route = respx.get(url__startswith=RPC_URL).mock(
        side_effect=[
            httpx.ConnectError("boom"),
            httpx.Response(200, json={"results": [make_package()]}),
        ]
    )
    info = fetch_meta("demo", sleep=lambda _: None)
    assert info.name == "demo"
    assert route.call_count == 2


@respx.mock
def test_fetch_meta_many_batches_and_pauses(
    make_package: Callable[..., dict[str, Any]],
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        names = request.url.params.get_list("arg[]")
        return httpx.Response(200, json={"results": [make_package(name) for name in names]})

    route = respx.get(url__startswith=RPC_URL).mock(side_effect=handler)
    names = [f"pkg{i}" for i in range(BATCH_SIZE + 1)]
    sleeps: list[float] = []

    packages = fetch_meta_many(names, sleep=sleeps.append)

    assert len(packages) == BATCH_SIZE + 1
    assert route.call_count == 2
    assert sleeps == [1.0]


@respx.mock
def test_fetch_meta_many_deduplicates() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        names = request.url.params.get_list("arg[]")
        return httpx.Response(
            200,
            json={
                "results": [
                    {
                        "Name": name,
                        "Version": "1-1",
                        "Maintainer": None,
                        "Submitter": None,
                        "FirstSubmitted": BASE_EPOCH,
                        "LastModified": BASE_EPOCH,
                        "NumVotes": 0,
                        "Popularity": 0.0,
                        "OutOfDate": None,
                        "URL": None,
                        "Depends": [],
                        "MakeDepends": [],
                        "OptDepends": [],
                    }
                    for name in names
                ]
            },
        )

    route = respx.get(url__startswith=RPC_URL).mock(side_effect=handler)
    packages = fetch_meta_many(["demo", "demo"])
    assert list(packages) == ["demo"]
    assert route.call_count == 1
    assert route.calls[0].request.url.params.get_list("arg[]") == ["demo"]


@respx.mock
def test_fetch_meta_uses_a_supplied_cache(
    tmp_path: Path,
    make_package: Callable[..., dict[str, Any]],
) -> None:
    route = respx.get(url__startswith=RPC_URL).mock(
        return_value=httpx.Response(200, json={"results": [make_package()]})
    )
    cache = ResponseCache(tmp_path / "cache")

    first = fetch_meta("demo", cache=cache)
    second = fetch_meta("demo", cache=cache)

    assert first == second
    assert route.call_count == 1


@respx.mock
def test_fetch_meta_does_not_cache_errors(tmp_path: Path) -> None:
    route = respx.get(url__startswith=RPC_URL).mock(
        side_effect=[
            httpx.Response(404),
            httpx.Response(200, json={"results": []}),
        ]
    )
    cache = ResponseCache(tmp_path / "cache")

    with pytest.raises(FetchError, match="HTTP 404"):
        fetch_meta("demo", cache=cache)
    with pytest.raises(FetchError, match="not found"):
        fetch_meta("demo", cache=cache)
    assert route.call_count == 2


def test_fetch_meta_many_empty_makes_no_request() -> None:
    with respx.mock(assert_all_called=False) as router:
        route = router.get(url__startswith=RPC_URL).mock(return_value=httpx.Response(200))
        assert fetch_meta_many([]) == {}
        assert not route.called
