"""Package-name validation and terminal-safe text sanitization."""

import re

from aurscan.errors import InvalidPackageNameError

_PACKAGE_NAME_RE = re.compile(r"^[a-z0-9@._+-]{1,255}$")

_OSC_RE = re.compile(r"\x1b\].*?(?:\x07|\x1b\\)", re.DOTALL)
_CSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_ESC_RE = re.compile(r"\x1b.")
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_WHITESPACE_RE = re.compile(r"\s+")

_BIDI_CHARS = frozenset(
    chr(codepoint)
    for start, end in ((0x061C, 0x061C), (0x200E, 0x200F), (0x202A, 0x202E), (0x2066, 0x2069))
    for codepoint in range(start, end + 1)
)


def validate_package_name(name: str) -> str:
    """Return ``name`` if it is a valid AUR package name, else raise."""
    if not _PACKAGE_NAME_RE.fullmatch(name):
        safe = sanitize_text(name, max_length=80)
        raise InvalidPackageNameError(f"invalid AUR package name: {safe!r}")
    return name


def sanitize_text(text: str, *, max_length: int = 200) -> str:
    """Strip terminal escapes and bidi controls, collapse whitespace, truncate.

    The result is safe to render with rich and is never longer than ``max_length``.
    """
    if max_length < 1:
        raise ValueError("max_length must be at least 1")

    cleaned = _OSC_RE.sub("", text)
    cleaned = _CSI_RE.sub("", cleaned)
    cleaned = _ESC_RE.sub("", cleaned)
    cleaned = "".join(char for char in cleaned if char not in _BIDI_CHARS)
    cleaned = _CONTROL_RE.sub(" ", cleaned)
    cleaned = _WHITESPACE_RE.sub(" ", cleaned).strip()

    if len(cleaned) > max_length:
        cleaned = cleaned[: max_length - 1].rstrip() + "…"
    return cleaned
