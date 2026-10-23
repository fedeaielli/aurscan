"""dir_fd-anchored, symlink-refusing file access inside a clone."""

from __future__ import annotations

import os
import stat
from collections.abc import Iterator
from pathlib import Path, PurePosixPath

from aurscan.errors import BinaryFileError, FileTooLargeError, SafetyError, UnsafePathError

MAX_TEXT_BYTES = 1024 * 1024
_MAX_ENTRIES = 10_000


def read_text_safe(
    root: Path,
    relative: str,
    *,
    max_bytes: int = MAX_TEXT_BYTES,
) -> str:
    """Read a regular UTF-8 file under ``root`` without following symlinks."""
    root_path = _root_path(root)
    parts = _relative_parts(relative)
    dir_fd = _open_root_dir(root_path)
    try:
        for part in parts[:-1]:
            next_fd = _open_dir_at(dir_fd, part, relative)
            os.close(dir_fd)
            dir_fd = next_fd
        try:
            file_fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dir_fd)
        except OSError as exc:
            raise UnsafePathError(f"cannot open path safely: {relative!r}") from exc
    finally:
        os.close(dir_fd)

    try:
        info = os.fstat(file_fd)
        if not stat.S_ISREG(info.st_mode):
            raise UnsafePathError(f"not a regular file: {relative!r}")
        if info.st_size > max_bytes:
            raise FileTooLargeError(f"file exceeds {max_bytes} bytes: {relative!r}")
        data = _read_limited(file_fd, max_bytes=max_bytes, relative=relative)
    finally:
        os.close(file_fd)

    if len(data) > max_bytes:
        raise FileTooLargeError(f"file exceeds {max_bytes} bytes: {relative!r}")
    if b"\x00" in data:
        raise BinaryFileError(f"binary file: {relative!r}")
    return data.decode("utf-8", errors="replace")


def iter_regular_files(root: Path, *, max_entries: int = _MAX_ENTRIES) -> Iterator[Path]:
    """Yield regular files under ``root``, never following symlinks."""
    for path in _walk_entries(root, max_entries=max_entries):
        if _is_regular_file(path):
            yield path


def _walk_entries(root: Path, *, max_entries: int) -> Iterator[Path]:
    """Yield every entry under ``root`` without descending into symlinks."""
    root_path = _root_path(root)
    seen = 0

    def _raise(error: OSError) -> None:
        raise SafetyError(f"cannot read directory: {root_path}") from error

    for directory, dirnames, filenames in os.walk(root_path, onerror=_raise):
        entries = [*dirnames, *filenames]
        seen += len(entries)
        if seen > max_entries:
            raise SafetyError(f"more than {max_entries} entries under {root_path}")
        for name in entries:
            yield Path(directory) / name


def _is_regular_file(path: Path) -> bool:
    try:
        return stat.S_ISREG(path.stat(follow_symlinks=False).st_mode)
    except OSError as exc:
        raise SafetyError(f"cannot inspect entry: {path}") from exc


def _root_path(root: Path) -> Path:
    try:
        root_path = Path(root).resolve(strict=True)
    except OSError as exc:
        raise UnsafePathError(f"root does not exist: {root}") from exc
    if not root_path.is_dir():
        raise UnsafePathError(f"root is not a directory: {root}")
    return root_path


def _open_root_dir(root: Path) -> int:
    try:
        return os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as exc:
        raise UnsafePathError(f"cannot open root safely: {root}") from exc


def _open_dir_at(dir_fd: int, part: str, relative: str) -> int:
    try:
        return os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dir_fd)
    except OSError as exc:
        raise UnsafePathError(f"cannot traverse path safely: {relative!r}") from exc


def _relative_parts(relative: str) -> tuple[str, ...]:
    if "\x00" in relative:
        raise UnsafePathError("path contains NUL byte")
    pure = PurePosixPath(relative)
    if pure.is_absolute():
        raise UnsafePathError(f"absolute path not allowed: {relative!r}")
    parts = pure.parts
    if not parts or any(part in ("", "..") for part in parts):
        raise UnsafePathError(f"path escapes root: {relative!r}")
    return parts


def _read_limited(file_fd: int, *, max_bytes: int, relative: str) -> bytes:
    chunks: list[bytes] = []
    remaining = max_bytes + 1
    while remaining > 0:
        chunk = os.read(file_fd, min(65536, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)
