"""On-disk HTTP response cache with TTL and atomic writes.

The cache is intentionally independent of :mod:`aurscan.fetch` for now; the CLI
wires it in (and gains ``--no-cache``) together with the rule engine.
"""

from __future__ import annotations

import hashlib
import os
import stat
import tempfile
import time
from collections.abc import Callable
from contextlib import suppress
from pathlib import Path

DEFAULT_TTL_SECONDS = 3600.0
MAX_ENTRY_BYTES = 1024 * 1024


class ResponseCache:
    """Cache HTTP bodies on disk, keyed by URL.

    Entries older than ``ttl`` seconds are reported as misses. Writes go to a
    temporary file and are atomically renamed into place, so readers never see a
    partial body. Cache failures are best-effort and never raise.
    """

    def __init__(
        self,
        directory: Path,
        *,
        ttl: float = DEFAULT_TTL_SECONDS,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._directory = Path(directory)
        self._ttl = ttl
        self._clock = clock

    @property
    def directory(self) -> Path:
        return self._directory

    def get(self, url: str) -> bytes | None:
        """Return the cached body for ``url``, or ``None`` on a miss."""
        path = self._entry_path(url)
        try:
            info = os.stat(path, follow_symlinks=False)
        except OSError:
            return None
        if not stat.S_ISREG(info.st_mode):
            return None
        if info.st_size > MAX_ENTRY_BYTES:
            return None
        if self._clock() - info.st_mtime >= self._ttl:
            return None
        try:
            data = self._read(path)
        except OSError:
            return None
        if len(data) > MAX_ENTRY_BYTES:
            return None
        return data

    def put(self, url: str, data: bytes) -> None:
        """Store ``data`` for ``url``. Failures are silently ignored."""
        path = self._entry_path(url)
        temporary: str | None = None
        try:
            self._directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            descriptor, temporary = tempfile.mkstemp(dir=self._directory, prefix=".tmp-")
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(data)
            os.chmod(temporary, 0o600)
            os.replace(temporary, path)
            temporary = None
        except OSError:
            return
        finally:
            if temporary is not None:
                with suppress(OSError):
                    os.unlink(temporary)

    def _entry_path(self, url: str) -> Path:
        digest = hashlib.sha256(url.encode("utf-8", errors="replace")).hexdigest()
        return self._directory / f"{digest}.body"

    @staticmethod
    def _read(path: Path) -> bytes:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "rb") as handle:
            return handle.read(MAX_ENTRY_BYTES + 1)


def default_cache_dir() -> Path:
    """Return ``$XDG_CACHE_HOME/aurscan`` or ``~/.cache/aurscan``."""
    base = os.environ.get("XDG_CACHE_HOME")
    root = Path(base) if base else Path.home() / ".cache"
    return root / "aurscan"
