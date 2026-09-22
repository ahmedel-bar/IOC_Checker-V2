"""
ioc/normalizer.py

Normalizes raw extracted IOC values so that equivalent representations
collapse into a single canonical form before counting/deduplication:

    EVIL.COM, evil.com, evil.com.   -> evil.com
    <HASH IN UPPERCASE>              -> lowercase
    010.010.000.001 (rare edge case) -> 10.10.0.1 (via ipaddress)
    URLs                             -> scheme + host lowercased, rest preserved

This layer is intentionally separate from extraction (artifacts/*.py) so
new extractors never need to reimplement normalization rules.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit, urlunsplit

from detector import IOCType


def _normalize_domain(value: str) -> str:
    return value.strip().lower().rstrip(".")


def _normalize_hash(value: str) -> str:
    return value.strip().lower()


def _normalize_ipv4(value: str) -> str:
    # Round-tripping through ipaddress canonicalizes formatting. Python's
    # ipaddress module rejects leading zeros in octets outright (they're
    # ambiguous - could imply octal), but our extraction regex doesn't
    # reject them, so strip them manually first (e.g. "010.010.000.001"
    # -> "10.10.0.1") rather than raising on otherwise-valid-looking input.
    stripped = value.strip()
    octets = stripped.split(".")
    if len(octets) == 4:
        octets = [str(int(o)) if o.isdigit() else o for o in octets]
        stripped = ".".join(octets)
    return str(ipaddress.IPv4Address(stripped))


def _normalize_url(value: str) -> str:
    value = value.strip()
    try:
        parts = urlsplit(value)
    except ValueError:
        return value

    scheme = parts.scheme.lower()
    netloc = parts.netloc.lower()
    # Preserve path/query exactly (case can be meaningful there); only the
    # scheme and host are safe to lowercase unconditionally. Drop any
    # fragment, which never affects what's actually requested over the wire.
    normalized = urlunsplit((scheme, netloc, parts.path, parts.query, ""))
    return normalized


def normalize_ioc(value: str, ioc_type: IOCType) -> str:
    """Return the canonical form of an IOC value for the given type."""
    if ioc_type == IOCType.DOMAIN:
        return _normalize_domain(value)
    if ioc_type in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256):
        return _normalize_hash(value)
    if ioc_type == IOCType.IPV4:
        return _normalize_ipv4(value)
    if ioc_type == IOCType.URL:
        return _normalize_url(value)
    return value.strip()
