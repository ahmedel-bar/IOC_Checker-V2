"""
artifacts/_encoding.py

Shared text-encoding detection for TextExtractor, LogExtractor, and
CSVExtractor. Files handed to -a/--artifact commonly originate from
Windows tooling - PowerShell's `>` / `Out-File` redirection defaults to
UTF-16 LE, and Notepad offers UTF-16 as an explicit save option - so
blindly decoding as UTF-8 silently produces zero extracted IOCs (each
ASCII character ends up separated by a NUL byte, which breaks every
extraction regex) without raising any error. Detecting the encoding from
the byte-order-mark up front avoids that failure mode entirely.
"""

from __future__ import annotations

import codecs

# Checked longest-prefix-first so UTF-32's 4-byte BOM isn't mistaken for
# UTF-16's 2-byte BOM (UTF-32 LE's BOM starts with the same two bytes as
# UTF-16 LE's).
_BOM_ENCODINGS: list[tuple[bytes, str]] = [
    (codecs.BOM_UTF32_LE, "utf-32"),
    (codecs.BOM_UTF32_BE, "utf-32"),
    (codecs.BOM_UTF8, "utf-8-sig"),
    (codecs.BOM_UTF16_LE, "utf-16"),
    (codecs.BOM_UTF16_BE, "utf-16"),
]


def detect_text_encoding(path: str) -> str:
    """
    Inspect the leading bytes of the file at `path` for a byte-order mark
    and return the matching Python codec name. Falls back to "utf-8" (the
    overwhelmingly common case for artifacts with no BOM) when none is
    found - callers should still open with errors="replace" as a final
    safety net against any remaining decode issues.
    """
    with open(path, "rb") as handle:
        head = handle.read(4)

    for bom, encoding in _BOM_ENCODINGS:
        if head.startswith(bom):
            return encoding

    return "utf-8"


def read_text_file(path: str) -> str:
    """Read a text-based artifact file using its detected encoding."""
    encoding = detect_text_encoding(path)
    with open(path, "r", encoding=encoding, errors="replace") as handle:
        return handle.read()
