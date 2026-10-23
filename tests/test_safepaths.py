"""Tests for dir_fd-anchored safe file access."""

from pathlib import Path

import pytest

from aurscan.errors import (
    BinaryFileError,
    FileTooLargeError,
    SafetyError,
    UnsafePathError,
)
from aurscan.safepaths import iter_regular_files, read_text_safe


@pytest.fixture
def root(tmp_path: Path) -> Path:
    clone = tmp_path / "root"
    (clone / "sub").mkdir(parents=True)
    (clone / "PKGBUILD").write_text("pkgname=demo\n", encoding="utf-8")
    (clone / "sub" / "demo.install").write_text("post_install() { :; }\n", encoding="utf-8")
    return clone


def test_read_text_safe_reads_nested_file(root: Path) -> None:
    assert read_text_safe(root, "PKGBUILD") == "pkgname=demo\n"
    assert read_text_safe(root, "sub/demo.install") == "post_install() { :; }\n"


def test_read_text_safe_rejects_traversal(root: Path) -> None:
    (root.parent / "outside").write_text("secret", encoding="utf-8")
    with pytest.raises(UnsafePathError):
        read_text_safe(root, "../outside")


def test_read_text_safe_rejects_absolute_path(root: Path) -> None:
    with pytest.raises(UnsafePathError):
        read_text_safe(root, "/etc/passwd")


def test_read_text_safe_rejects_empty_path(root: Path) -> None:
    with pytest.raises(UnsafePathError):
        read_text_safe(root, "")


def test_read_text_safe_rejects_symlink_file(root: Path) -> None:
    (root / "link").symlink_to(root / "PKGBUILD")
    with pytest.raises(UnsafePathError):
        read_text_safe(root, "link")


def test_read_text_safe_rejects_symlinked_directory(root: Path) -> None:
    outside = root.parent / "outside"
    outside.mkdir()
    (outside / "secret").write_text("secret", encoding="utf-8")
    (root / "dirlink").symlink_to(outside, target_is_directory=True)
    with pytest.raises(UnsafePathError):
        read_text_safe(root, "dirlink/secret")


def test_read_text_safe_rejects_binary(root: Path) -> None:
    (root / "blob").write_bytes(b"a\x00b")
    with pytest.raises(BinaryFileError):
        read_text_safe(root, "blob")


def test_read_text_safe_enforces_size_limit(root: Path) -> None:
    (root / "big").write_text("abcd", encoding="utf-8")
    with pytest.raises(FileTooLargeError):
        read_text_safe(root, "big", max_bytes=3)


def test_read_text_safe_replaces_invalid_utf8(root: Path) -> None:
    (root / "latin1").write_bytes(b"\xff")
    assert read_text_safe(root, "latin1") == "\ufffd"


def test_read_text_safe_missing_root(tmp_path: Path) -> None:
    with pytest.raises(UnsafePathError):
        read_text_safe(tmp_path / "nope", "PKGBUILD")


def test_iter_regular_files_skips_symlinks(root: Path) -> None:
    (root / "link").symlink_to(root / "PKGBUILD")
    relative = {path.relative_to(root).as_posix() for path in iter_regular_files(root)}
    assert relative == {"PKGBUILD", "sub/demo.install"}


def test_walk_enforces_entry_limit(root: Path) -> None:
    (root / "extra").write_text("x", encoding="utf-8")
    (root / "more").write_text("x", encoding="utf-8")
    with pytest.raises(SafetyError, match="entries"):
        list(iter_regular_files(root, max_entries=2))
