"""
detector.py

Detects the type of an Indicator of Compromise (IOC) supplied by the user.
Supports: IPv4, Domain, URL, MD5, SHA1, SHA256.

Domain classification specifically delegates to domain_validation.py -
the single canonical domain validator also used by artifact extraction
(artifacts/_scan.py) and provider-side input validation
(providers/otx.py, providers/threatfox.py). This is deliberate: a value
must be classified identically regardless of whether it came from the
command line or from inside an artifact, so there is exactly one
implementation of "is this a domain" for the whole project to share.
"""

from __future__ import annotations

import ipaddress
import re
from enum import Enum

from domain_validation import is_valid_domain


class IOCType(str, Enum):
    IPV4 = "IPv4"
    DOMAIN = "Domain"
    URL = "URL"
    MD5 = "MD5"
    SHA1 = "SHA1"
    SHA256 = "SHA256"
    UNKNOWN = "Unknown"


_MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
_SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")


def _is_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False


def _is_url(value: str) -> bool:
    return value.lower().startswith(("http://", "https://", "ftp://"))


def detect_ioc_type(raw_value: str) -> IOCType:
    """
    Inspect the given string and classify it as one of the supported
    IOC types. Order of checks matters: hashes are unambiguous fixed-length
    hex strings, so they are checked before domain/URL/IP.
    """
    value = raw_value.strip()

    if not value:
        return IOCType.UNKNOWN

    if _is_url(value):
        return IOCType.URL

    if _is_ipv4(value):
        return IOCType.IPV4

    if _SHA256_RE.match(value):
        return IOCType.SHA256

    if _SHA1_RE.match(value):
        return IOCType.SHA1

    if _MD5_RE.match(value):
        return IOCType.MD5

    if is_valid_domain(value):
        return IOCType.DOMAIN

    return IOCType.UNKNOWN
