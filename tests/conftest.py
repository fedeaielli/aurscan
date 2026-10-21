"""Shared test fixtures and payload factories."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

BASE_EPOCH = 1_700_000_000


@pytest.fixture
def make_package() -> Callable[..., dict[str, Any]]:
    """Return a factory for AUR RPC package payloads."""

    def _make(name: str = "demo", **overrides: Any) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "Name": name,
            "Version": "1.2.3-1",
            "Maintainer": "maintainer",
            "Submitter": "submitter",
            "FirstSubmitted": BASE_EPOCH,
            "LastModified": BASE_EPOCH + 3600,
            "NumVotes": 42,
            "Popularity": 1.5,
            "OutOfDate": None,
            "URL": "https://example.invalid/demo",
            "Depends": ["glibc"],
            "MakeDepends": ["gcc"],
            "OptDepends": ["bash: for scripts"],
        }
        payload.update(overrides)
        return payload

    return _make


@pytest.fixture(autouse=True)
def _isolate_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep every test away from the real on-disk HTTP cache."""
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache-home"))
