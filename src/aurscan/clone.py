"""Hardened git clone for AUR package repositories."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from aurscan.errors import CloneError
from aurscan.validation import validate_package_name

DEFAULT_TIMEOUT_SECONDS = 60.0
MAX_CLONE_BYTES = 50 * 1024 * 1024

_CLONE_FLAGS = ("--single-branch", "--no-tags", "--no-recurse-submodules")
_STRIPPED_GIT_ENV = frozenset(
    {
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_NAMESPACE",
        "GIT_COMMON_DIR",
    }
)


def clone_package(
    name: str,
    dest: Path,
    *,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    url: str | None = None,
    max_bytes: int = MAX_CLONE_BYTES,
    depth: int = 1,
) -> Path:
    """Clone ``name`` into ``dest`` with hooks, submodules and extra history disabled.

    ``dest`` must not exist. ``depth`` controls how many commits are fetched;
    history analysis uses ``n + 1`` so the oldest of ``n`` commits still has a
    parent available for its diff. The clone is removed and ``CloneError`` raised
    if git fails, times out, or checks out more than ``max_bytes``.
    """
    validate_package_name(name)
    if depth < 1:
        raise CloneError("clone depth must be at least 1")
    dest = Path(dest)
    if dest.exists():
        raise CloneError(f"clone destination already exists: {dest}")

    remote = url if url is not None else f"https://aur.archlinux.org/{name}.git"
    command = [
        "git",
        "-c",
        "core.hooksPath=/dev/null",
        "clone",
        "--depth",
        str(depth),
        *_CLONE_FLAGS,
        "--",
        remote,
        str(dest),
    ]

    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
            env=git_env(),
        )
    except FileNotFoundError as exc:
        raise CloneError("git executable not found") from exc
    except subprocess.TimeoutExpired as exc:
        _remove_clone(dest)
        raise CloneError(f"git clone timed out after {timeout:g} seconds") from exc

    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        _remove_clone(dest)
        raise CloneError(f"git clone failed for {name}: {detail[:500]}")

    size = _directory_size(dest, max_bytes=max_bytes)
    if size > max_bytes:
        _remove_clone(dest)
        raise CloneError(f"cloned repository exceeds {max_bytes} bytes")

    return dest


def git_env() -> dict[str, str]:
    """Return an environment for hardened git invocations."""
    env = {key: value for key, value in os.environ.items() if key not in _STRIPPED_GIT_ENV}
    env["GIT_TERMINAL_PROMPT"] = "0"
    return env


def _remove_clone(dest: Path) -> None:
    shutil.rmtree(dest, ignore_errors=True)


def _directory_size(root: Path, *, max_bytes: int) -> int:
    total = 0
    stack = [root]
    while stack:
        try:
            with os.scandir(stack.pop()) as entries:
                for entry in entries:
                    try:
                        if entry.is_symlink():
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(Path(entry.path))
                        elif entry.is_file(follow_symlinks=False):
                            total += entry.stat(follow_symlinks=False).st_size
                            if total > max_bytes:
                                return total
                    except OSError:
                        continue
        except OSError:
            continue
    return total
