"""AUR RPC v5 metadata retrieval."""

from __future__ import annotations

import json
import random
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlencode

import httpx
from pydantic import ValidationError

from aurscan.errors import FetchError
from aurscan.models import PackageInfo
from aurscan.validation import validate_package_name

USER_AGENT = "aurscan/0.1 (+contact)"
RPC_URL = "https://aur.archlinux.org/rpc/v5/info"
MAX_BODY_BYTES = 1024 * 1024
MAX_RETRIES = 3
BATCH_SIZE = 50
BATCH_PAUSE_SECONDS = 1.0


class _RetryableFailure(Exception):
    """Internal marker for failures worth retrying."""


def http_get(
    url: str,
    *,
    timeout: float = 10.0,
    client: httpx.Client | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> bytes:
    """GET ``url`` and return the body, retrying transient failures.

    Redirects are not followed and bodies larger than ``MAX_BODY_BYTES`` are rejected.
    """
    owns_client = client is None
    if client is None:
        client = httpx.Client(trust_env=False, follow_redirects=False, timeout=timeout)
    try:
        return _get_with_retries(client, url, timeout=timeout, sleep=sleep)
    finally:
        if owns_client:
            client.close()


def _get_with_retries(
    client: httpx.Client,
    url: str,
    *,
    timeout: float,
    sleep: Callable[[float], None],
) -> bytes:
    last_message = "unknown error"
    for attempt in range(MAX_RETRIES + 1):
        try:
            return _get_once(client, url, timeout=timeout)
        except _RetryableFailure as exc:
            last_message = str(exc)
            if attempt < MAX_RETRIES:
                sleep(_backoff(attempt))
    raise FetchError(f"request to {url} failed after {MAX_RETRIES + 1} attempts: {last_message}")


def _get_once(client: httpx.Client, url: str, *, timeout: float) -> bytes:
    try:
        with client.stream(
            "GET", url, timeout=timeout, headers={"User-Agent": USER_AGENT}
        ) as response:
            status = response.status_code
            if status == 200:
                declared = response.headers.get("content-length")
                if declared is not None and declared.isdigit() and int(declared) > MAX_BODY_BYTES:
                    raise FetchError(f"response from {url} exceeds {MAX_BODY_BYTES} bytes")
                chunks: list[bytes] = []
                total = 0
                for chunk in response.iter_bytes():
                    total += len(chunk)
                    if total > MAX_BODY_BYTES:
                        raise FetchError(f"response from {url} exceeds {MAX_BODY_BYTES} bytes")
                    chunks.append(chunk)
                return b"".join(chunks)
            if status == 429 or 500 <= status < 600:
                raise _RetryableFailure(f"HTTP {status} from {url}")
            raise FetchError(f"HTTP {status} from {url}")
    except httpx.HTTPError as exc:
        raise _RetryableFailure(f"{type(exc).__name__}: {exc}") from exc


def _backoff(attempt: int) -> float:
    base = 0.5 * float(2**attempt)
    jitter: float = random.uniform(0.0, 0.25)
    return base + jitter


def fetch_meta(
    name: str,
    *,
    timeout: float = 10.0,
    client: httpx.Client | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> PackageInfo:
    """Fetch metadata for a single AUR package."""
    validate_package_name(name)
    results = _rpc_request([name], timeout=timeout, client=client, sleep=sleep)
    if not results:
        raise FetchError(f"package not found: {name}")
    return _parse_package(results[0])


def fetch_meta_many(
    names: Sequence[str],
    *,
    timeout: float = 10.0,
    client: httpx.Client | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, PackageInfo]:
    """Fetch metadata for several packages, batching requests at ``BATCH_SIZE``.

    Returns only packages the AUR reported, keyed by their canonical name.
    """
    unique_names = list(dict.fromkeys(names))
    for name in unique_names:
        validate_package_name(name)

    packages: dict[str, PackageInfo] = {}
    for index, batch in enumerate(_chunks(unique_names, BATCH_SIZE)):
        if index:
            sleep(BATCH_PAUSE_SECONDS)
        results = _rpc_request(batch, timeout=timeout, client=client, sleep=sleep)
        for raw in results:
            info = _parse_package(raw)
            packages[info.name] = info
    return packages


def _chunks(items: Sequence[str], size: int) -> Iterable[list[str]]:
    for start in range(0, len(items), size):
        yield list(items[start : start + size])


def _rpc_request(
    names: Sequence[str],
    *,
    timeout: float,
    client: httpx.Client | None,
    sleep: Callable[[float], None],
) -> list[object]:
    if not names:
        return []
    query = urlencode([("arg[]", name) for name in names])
    body = http_get(f"{RPC_URL}?{query}", timeout=timeout, client=client, sleep=sleep)
    try:
        payload: Any = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise FetchError("invalid JSON from AUR RPC") from exc
    if not isinstance(payload, dict):
        raise FetchError("unexpected AUR RPC response")
    error = payload.get("error")
    if error:
        raise FetchError(f"AUR RPC error: {error}")
    results = payload.get("results")
    if not isinstance(results, list):
        raise FetchError("AUR RPC response is missing results")
    return results


def _parse_package(raw: object) -> PackageInfo:
    if not isinstance(raw, dict):
        raise FetchError("malformed AUR metadata: result is not an object")
    data: dict[str, object] = {
        "name": _required_str(raw, "Name"),
        "version": _required_str(raw, "Version"),
        "maintainer": _optional_str(raw, "Maintainer"),
        "submitter": _optional_str(raw, "Submitter"),
        "first_submitted": _required_epoch(raw, "FirstSubmitted"),
        "last_modified": _required_epoch(raw, "LastModified"),
        "num_votes": _required_int(raw, "NumVotes"),
        "popularity": _required_float(raw, "Popularity"),
        "out_of_date": _optional_epoch(raw, "OutOfDate"),
        "url": _optional_str(raw, "URL"),
        "depends": _str_list(raw, "Depends"),
        "make_depends": _str_list(raw, "MakeDepends"),
        "opt_depends": _str_list(raw, "OptDepends"),
    }
    try:
        return PackageInfo.model_validate(data)
    except ValidationError as exc:
        raise FetchError("malformed AUR metadata") from exc


def _required_str(raw: Mapping[str, object], key: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value:
        raise FetchError(f"malformed AUR metadata: invalid {key}")
    return value


def _optional_str(raw: Mapping[str, object], key: str) -> str | None:
    value = raw.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise FetchError(f"malformed AUR metadata: invalid {key}")
    return value or None


def _required_int(raw: Mapping[str, object], key: str) -> int:
    value = raw.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        raise FetchError(f"malformed AUR metadata: invalid {key}")
    return value


def _required_float(raw: Mapping[str, object], key: str) -> float:
    value = raw.get(key)
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise FetchError(f"malformed AUR metadata: invalid {key}")
    return float(value)


def _required_epoch(raw: Mapping[str, object], key: str) -> datetime:
    return datetime.fromtimestamp(_positive_epoch(raw, key), tz=UTC)


def _optional_epoch(raw: Mapping[str, object], key: str) -> datetime | None:
    value = raw.get(key)
    if value is None:
        return None
    return datetime.fromtimestamp(_positive_epoch(raw, key), tz=UTC)


def _positive_epoch(raw: Mapping[str, object], key: str) -> int:
    value = _required_int(raw, key)
    if value <= 0:
        raise FetchError(f"malformed AUR metadata: invalid {key}")
    return value


def _str_list(raw: Mapping[str, object], key: str) -> list[str]:
    value = raw.get(key)
    if value is None:
        return []
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise FetchError(f"malformed AUR metadata: invalid {key}")
    return [item for item in value if isinstance(item, str)]
