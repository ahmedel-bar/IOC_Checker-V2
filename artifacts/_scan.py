"""
artifacts/_scan.py

Shared regex-based IOC scanning used by TextExtractor, LogExtractor, and
CSVExtractor (CSV cells are just scanned as text too - see csv_extractor.py).
Keeping this in one place means the extraction rules only need to be
correct, tuned, and tested once. Text is treated as arbitrary
human-written content - there is no required format, column structure,
or one-IOC-per-line convention; the regexes simply scan for matches
wherever they occur.

Extraction order matters:
    1. Hashes (SHA256 / SHA1 / MD5) - exact-length hex runs, unambiguous.
    2. URLs - the URL itself is emitted, then its matched span is blanked
       out of the working text immediately (before any IP/domain scan
       runs). URLs take full precedence over anything nested inside
       them: neither an IP nor a domain used as a URL's host is
       additionally emitted as its own IOC (http://105.224.244.218/x and
       http://evil.com/x each produce only the URL, never a second
       IPv4/Domain IOC for the same occurrence). If the same IP or
       domain also appears standalone elsewhere in the text, that
       occurrence is still picked up normally by step 3/4 below, since
       blanking only removes the URL's own matched span, not other
       occurrences of the same value.
    3. Remaining bare IPv4 addresses are classified internal/external
       (via ip_classification.is_internal_ipv4) at the moment they're
       found, so that classification never needs to be redone later.
    4. Remaining bare domains, validated against real TLD/public-suffix
       data (via domain_validation.is_valid_domain) rather than a
       blacklist of "known bad" file extensions - this is what tells
       "evil.example.com" (real domain) apart from "wp-cron.php" or
       "index.html" (filenames that only superficially look the same).

IPv6 is never matched by any of these patterns - it is intentionally out
of scope for this feature.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Iterator

from artifacts.base import RawIOC
from detector import IOCType
from domain_validation import is_valid_domain
from ip_classification import is_internal_ipv4

# --- Hash patterns -----------------------------------------------------
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
_SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")

# --- URL pattern ---------------------------------------------------------
_URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>\]\)]+", re.IGNORECASE)

# --- IPv4 pattern (bounded octets, avoids matching version-like numbers
# such as 999.999.999.999 which aren't valid addresses - validity is
# double-checked with ipaddress before acceptance anyway) -----------------
_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)

# --- Domain candidate pattern -----------------------------------------------
# Deliberately permissive: matches the ENTIRE contiguous run of
# dot-separated labels, with no constraint on the final label's length or
# character class. This is intentional - see the note below the regex.
_DOMAIN_CANDIDATE_RE = re.compile(
    r"\b[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)+\b"
)
# Why not validate the shape directly in this regex (as an earlier version
# did)? A regex that also enforces "final label is 2-63 letters" invites
# backtracking: for input like "th.bing.c", a regex requiring that shape
# will fail to match the whole string (final label "c" is 1 char) and then
# *backtrack* to matching just "th.bing" instead - silently dropping the
# trailing ".c" and treating "th.bing" as a standalone candidate. Since
# ".bing" happens to be a genuine, currently-delegated gTLD, that truncated
# candidate would then incorrectly pass validation. Separating "find the
# whole candidate span" (permissive, no backtracking possible since there's
# no shape constraint to fail and retry against) from "validate this exact
# candidate" (strict, all-or-nothing, in domain_validation.is_valid_domain)
# eliminates that failure mode entirely: "th.bing.c" is validated as one
# unit and correctly rejected as a whole, never silently truncated.


def _blank_span(text: str, start: int, end: int) -> str:
    """Replace text[start:end] with spaces, preserving all other offsets."""
    return text[:start] + (" " * (end - start)) + text[end:]


def _valid_ipv4(candidate: str) -> bool:
    try:
        ipaddress.IPv4Address(candidate)
        return True
    except ValueError:
        return False


def scan_text_for_iocs(text: str) -> Iterator[RawIOC]:
    """Scan a block of text and yield every IOC occurrence found."""
    if not text:
        return

    working = text

    # 1. Hashes first (longest/most specific pattern first so a SHA256
    #    substring is never later re-matched as something shorter - in
    #    practice \b boundaries already prevent this, but scanning
    #    longest-first keeps the intent explicit).
    for pattern, ioc_type in (
        (_SHA256_RE, IOCType.SHA256),
        (_SHA1_RE, IOCType.SHA1),
        (_MD5_RE, IOCType.MD5),
    ):
        for match in pattern.finditer(working):
            yield RawIOC(value=match.group(0), ioc_type=ioc_type)
        working = pattern.sub(lambda m: " " * len(m.group(0)), working)

    # 2. URLs - emit the URL itself, then blank its matched span so the
    #    bare IPv4/domain scans below never see it. URLs take full
    #    precedence over anything nested inside them - neither an IP nor
    #    a domain used as a URL's host is separately emitted here.
    url_spans: list[tuple[int, int]] = []
    for match in _URL_RE.finditer(working):
        url = match.group(0).rstrip(".,;:!?")
        yield RawIOC(value=url, ioc_type=IOCType.URL)
        url_spans.append((match.start(), match.start() + len(url)))

    for start, end in url_spans:
        working = _blank_span(working, start, end)

    # 3. Remaining bare IPv4 addresses - classified internal/external
    #    right here, at the moment each address is found.
    ipv4_spans: list[tuple[int, int]] = []
    for match in _IPV4_RE.finditer(working):
        candidate = match.group(0)
        if _valid_ipv4(candidate):
            yield RawIOC(
                value=candidate,
                ioc_type=IOCType.IPV4,
                is_internal=is_internal_ipv4(candidate),
            )
            ipv4_spans.append((match.start(), match.end()))

    for start, end in ipv4_spans:
        working = _blank_span(working, start, end)

    # 4. Remaining bare domains. Each match is the FULL contiguous dotted
    #    token (see _DOMAIN_CANDIDATE_RE note above on why no partial/
    #    truncated match is ever considered), validated as one all-or-
    #    nothing unit against real TLD/public-suffix data - this is what
    #    correctly rejects filenames like "wp-cron.php" or "index.html"
    #    (no such TLD exists) while still accepting real domains like
    #    "evil.example.com".
    for match in _DOMAIN_CANDIDATE_RE.finditer(working):
        candidate = match.group(0).strip(".")
        if not candidate:
            continue
        if not is_valid_domain(candidate):
            continue
        yield RawIOC(value=candidate, ioc_type=IOCType.DOMAIN)
