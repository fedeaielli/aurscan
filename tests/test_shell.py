"""Tests for shell-word helpers. Nothing is executed."""

from __future__ import annotations

from aurscan.shell import basename, split_words


def test_split_words_honours_quotes_and_escapes() -> None:
    assert split_words("curl -fsSL 'a b' \"c d\" e\\ f") == [
        "curl",
        "-fsSL",
        "a b",
        "c d",
        "e f",
    ]


def test_split_words_keeps_variables_unexpanded() -> None:
    assert split_words('"$url/file.tar.gz"') == ["$url/file.tar.gz"]
    assert split_words("$pkgdir/usr/bin/demo") == ["$pkgdir/usr/bin/demo"]


def test_split_words_empty_input() -> None:
    assert split_words("") == []
    assert split_words("   ") == []


def test_split_words_unbalanced_quote_falls_back() -> None:
    assert split_words("foo 'bar") == ["foo", "'bar"]


def test_basename() -> None:
    assert basename("/usr/bin/curl") == "curl"
    assert basename("curl") == "curl"
    assert basename("dir/") == "dir"
    assert basename("") == ""
