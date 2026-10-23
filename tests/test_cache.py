"""Tests for the on-disk response cache."""

from __future__ import annotations

import hashlib
import logging
import os
from pathlib import Path

import pytest

import aurscan.cache as cache_module
from aurscan.cache import MAX_ENTRY_BYTES, ResponseCache, default_cache_dir

URL = "https://example.invalid/PKGBUILD"


def _entry(directory: Path, url: str = URL) -> Path:
    digest = hashlib.sha256(url.encode("utf-8")).hexdigest()
    return directory / f"{digest}.body"


def test_roundtrip(tmp_path: Path) -> None:
    cache = ResponseCache(tmp_path)

    assert cache.get(URL) is None
    cache.put(URL, b"body")
    assert cache.get(URL) == b"body"


def test_urls_are_isolated(tmp_path: Path) -> None:
    cache = ResponseCache(tmp_path)
    cache.put(URL, b"one")
    cache.put("https://example.invalid/other", b"two")

    assert cache.get(URL) == b"one"
    assert cache.get("https://example.invalid/other") == b"two"


def test_put_is_atomic_and_leaves_no_temp_files(tmp_path: Path) -> None:
    cache = ResponseCache(tmp_path)
    cache.put(URL, b"first")
    cache.put(URL, b"second")

    assert cache.get(URL) == b"second"
    assert [path.name for path in tmp_path.iterdir()] == [_entry(tmp_path).name]


def test_entries_expire(tmp_path: Path) -> None:
    now = [0.0]
    cache = ResponseCache(tmp_path, ttl=10.0, clock=lambda: now[0])
    cache.put(URL, b"body")
    written = _entry(tmp_path).stat().st_mtime

    now[0] = written + 5.0
    assert cache.get(URL) == b"body"

    now[0] = written + 10.0
    assert cache.get(URL) is None


def test_zero_ttl_disables_cache(tmp_path: Path) -> None:
    cache = ResponseCache(tmp_path, ttl=0.0)
    cache.put(URL, b"body")

    assert cache.get(URL) is None


def test_corrupt_entry_is_a_miss(tmp_path: Path) -> None:
    cache = ResponseCache(tmp_path)
    cache.put(URL, b"body")
    _entry(tmp_path).write_bytes(b"replaced")
    assert cache.get(URL) == b"replaced"

    _entry(tmp_path).unlink()
    assert cache.get(URL) is None


def test_symlink_entry_is_not_followed(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.write_bytes(b"attacker")
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    _entry(cache_dir).symlink_to(outside)

    cache = ResponseCache(cache_dir)

    assert cache.get(URL) is None


def test_oversized_entry_is_a_miss(tmp_path: Path) -> None:
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    _entry(cache_dir).write_bytes(b"x" * (MAX_ENTRY_BYTES + 1))

    assert ResponseCache(cache_dir).get(URL) is None


def test_put_failure_does_not_raise(tmp_path: Path) -> None:
    blocker = tmp_path / "blocked"
    blocker.write_text("not a directory", encoding="utf-8")

    ResponseCache(blocker / "cache").put(URL, b"body")


def test_temp_removal_failure_is_logged(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    cache = ResponseCache(tmp_path)

    def failing_replace(*_args: object, **_kwargs: object) -> None:
        raise OSError("replace failed")

    def failing_unlink(*_args: object, **_kwargs: object) -> None:
        raise PermissionError("denied")

    monkeypatch.setattr(cache_module.os, "replace", failing_replace)
    monkeypatch.setattr(cache_module.os, "unlink", failing_unlink)

    with caplog.at_level(logging.WARNING, logger="aurscan.cache"):
        cache.put(URL, b"body")

    assert "could not remove temporary cache file" in caplog.text
    assert "denied" in caplog.text


def test_default_cache_dir_uses_xdg(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    assert default_cache_dir() == tmp_path / "aurscan"


def test_default_cache_dir_falls_back_to_home(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    assert default_cache_dir() == tmp_path / ".cache" / "aurscan"


def test_permissions_are_restrictive(tmp_path: Path) -> None:
    directory = tmp_path / "cache"
    ResponseCache(directory).put(URL, b"body")

    assert os.stat(directory).st_mode & 0o777 == 0o700
    assert os.stat(_entry(directory)).st_mode & 0o777 == 0o600
