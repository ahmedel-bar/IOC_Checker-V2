"""
utils.py

Shared utilities: logging setup and the unified result data structures
that every provider module must return, regardless of the underlying
API's native response format.
"""

from __future__ import annotations

import hashlib
import logging
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import TypedDict


def setup_logging() -> logging.Logger:
    """Configure and return the application-wide logger."""
    logger = logging.getLogger("ioc_checker")
    if not logger.handlers:
        handler = logging.FileHandler("ioc_checker.log")
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger


class Verdict(str, Enum):
    """Normalized verdict returned by every provider."""

    MALICIOUS = "MALICIOUS"
    SUSPICIOUS = "SUSPICIOUS"
    CLEAN = "CLEAN"
    FOUND = "FOUND"          # e.g. ThreatFox has a match but no clean/malicious axis
    NOT_FOUND = "NOT FOUND"
    RATE_LIMITED = "RATE LIMITED"  # provider throttled the request (HTTP 429) - not clean, not malicious
    ERROR = "ERROR"
    UNSUPPORTED = "UNSUPPORTED"  # provider does not support this IOC type


@dataclass
class ProviderResult:
    """
    Unified result format returned by every provider module.
    The main application only ever interacts with this shape, never with
    a provider's raw JSON response.
    """

    provider: str
    verdict: Verdict
    details: str
    risk_contribution: int = 0  # points this provider contributes to overall score
    raw: dict = field(default_factory=dict)


# Number of bytes read per iteration when hashing a file. A moderate chunk
# size keeps memory usage flat and constant even for files larger than the
# available RAM (e.g. multi-gigabyte samples).
_HASH_CHUNK_SIZE: int = 8192


class FileHashes(TypedDict):
    """Return shape of :func:`calculate_file_hashes`."""

    filename: str
    size: int
    md5: str
    sha1: str
    sha256: str


def calculate_file_hashes(path: str) -> FileHashes:
    """
    Calculate the MD5, SHA1, and SHA256 digests of a local file.

    The file is read incrementally in fixed-size chunks so that memory
    usage stays constant regardless of file size. This makes the function
    safe for very large files, including those larger than 2 GB, without
    ever loading the whole file into memory.

    Args:
        path: Path to the local file to hash.

    Returns:
        A :class:`FileHashes` mapping with the file's basename, size in
        bytes, and lowercase hex digests for ``md5``, ``sha1`` and
        ``sha256``.

    Raises:
        FileNotFoundError: If ``path`` does not exist.
        IsADirectoryError: If ``path`` refers to a directory.
        OSError: If the file cannot be read for any other reason.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"File not found: {path}")
    if os.path.isdir(path):
        raise IsADirectoryError(f"Path is a directory, not a file: {path}")

    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with open(path, "rb") as handle:
        # Using an iterator with a sentinel keeps peak memory bounded by
        # _HASH_CHUNK_SIZE, so 2 GB+ files hash without exhausting RAM.
        for chunk in iter(lambda: handle.read(_HASH_CHUNK_SIZE), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return FileHashes(
        filename=os.path.basename(path),
        size=os.path.getsize(path),
        md5=md5.hexdigest(),
        sha1=sha1.hexdigest(),
        sha256=sha256.hexdigest(),
    )
