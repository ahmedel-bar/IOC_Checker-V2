"""
providers/threatfox.py

abuse.ch ThreatFox provider.

Docs: https://threatfox.abuse.ch/api/
ThreatFox exposes a single POST endpoint that accepts a "search_ioc" query
for IPs, domains, URLs, and hashes alike (all four are supported by this
endpoint - the fix here is not about type support, but about validating
that the value handed to it actually looks like a well-formed instance
of its claimed type).

search_ioc rejects search terms that are empty, whitespace-only, or too
short with a query_status of "illegal_search_term". Extraction should
never hand ThreatFox something malformed (see artifacts/_scan.py and
domain_validation.py), but validating here too - defense-in-depth, same
reasoning as providers/otx.py - means we skip the doomed request entirely
instead of making it and then having to interpret the error.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from urllib.parse import urlparse

import requests

from providers import BaseProvider
from providers.http_utils import is_rate_limited, request_with_retry
from utils import ProviderResult, Verdict
from detector import IOCType
from domain_validation import is_valid_domain

logger = logging.getLogger("ioc_checker")

API_URL = "https://threatfox-api.abuse.ch/api/v1/"

# ThreatFox's search_ioc rejects search terms shorter than this with
# "illegal_search_term". Not tied to any specific IOC type - it's a
# blanket minimum the endpoint itself enforces.
_MIN_SEARCH_TERM_LENGTH = 3

_HASH_RE = {
    32: re.compile(r"^[a-fA-F0-9]{32}$"),
    40: re.compile(r"^[a-fA-F0-9]{40}$"),
    64: re.compile(r"^[a-fA-F0-9]{64}$"),
}


class ThreatFoxProvider(BaseProvider):
    name = "ThreatFox"
    SUPPORTED_TYPES = {
        IOCType.IPV4,
        IOCType.DOMAIN,
        IOCType.URL,
        IOCType.MD5,
        IOCType.SHA1,
        IOCType.SHA256,
    }

    def __init__(self, api_key: str | None, timeout: int = 15) -> None:
        self.api_key = api_key
        self.timeout = timeout

    def _headers(self) -> dict:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Auth-Key"] = self.api_key
        return headers

    def _not_configured(self) -> ProviderResult:
        return ProviderResult(
            provider=self.name,
            verdict=Verdict.ERROR,
            details="API key not configured",
        )

    def _invalid_input(self, ioc: str, reason: str) -> ProviderResult:
        logger.warning("ThreatFox skipping invalid value %r: %s", ioc, reason)
        return ProviderResult(
            provider=self.name,
            verdict=Verdict.ERROR,
            details=f"Skipped - {reason}",
        )

    def _search_ioc(self, ioc: str) -> ProviderResult:
        if not self.api_key:
            return self._not_configured()

        term = ioc.strip()
        if len(term) < _MIN_SEARCH_TERM_LENGTH:
            return self._invalid_input(
                ioc, f"search term too short (minimum {_MIN_SEARCH_TERM_LENGTH} characters)"
            )

        try:
            response = request_with_retry(
                lambda: requests.post(
                    API_URL,
                    json={"query": "search_ioc", "search_term": term},
                    headers=self._headers(),
                    timeout=self.timeout,
                ),
                self.name,
            )

            if is_rate_limited(response):
                return ProviderResult(
                    provider=self.name,
                    verdict=Verdict.RATE_LIMITED,
                    details="Rate limit exceeded - request skipped, try again later",
                )
            if not response.ok:
                return ProviderResult(
                    provider=self.name,
                    verdict=Verdict.ERROR,
                    details=f"Unavailable (HTTP {response.status_code})",
                )

            data = response.json()

            query_status = data.get("query_status")
            if query_status == "no_result":
                return ProviderResult(
                    provider=self.name,
                    verdict=Verdict.NOT_FOUND,
                    details="No match found",
                )
            if query_status == "illegal_search_term":
                # ThreatFox can reject an otherwise perfectly valid,
                # well-formed search term outright (this is distinct from
                # the local pre-request shape/length validation above,
                # which only catches obviously malformed input before it
                # ever reaches the API). This is not a statement about the
                # IOC itself - other providers (e.g. URLhaus) may still
                # return a real result for the same value - so it must
                # never surface as a provider ERROR/UNSUPPORTED, never
                # contribute risk, and never show up in API WARNINGS. The
                # closest honest equivalent is "ThreatFox has no usable
                # match for this search term", i.e. the same shape as a
                # genuine no_result/empty-data response below.
                return ProviderResult(
                    provider=self.name,
                    verdict=Verdict.NOT_FOUND,
                    details="No match found",
                )
            if query_status != "ok":
                return ProviderResult(
                    provider=self.name,
                    verdict=Verdict.ERROR,
                    details=f"API status: {query_status}",
                )

            entries = data.get("data", [])
            if not entries:
                return ProviderResult(
                    provider=self.name,
                    verdict=Verdict.NOT_FOUND,
                    details="No match found",
                )

            top = entries[0]
            malware = top.get("malware_printable", "Unknown")
            confidence = top.get("confidence_level", "N/A")
            ioc_type_str = top.get("ioc_type", "N/A")
            details = (
                f"Malware Family: {malware}\n"
                f"Confidence: {confidence}\n"
                f"IOC Type: {ioc_type_str}"
            )

            return ProviderResult(
                provider=self.name,
                verdict=Verdict.FOUND,
                details=details,
                risk_contribution=30,
                raw=data,
            )
        except requests.Timeout:
            logger.error("ThreatFox request timed out after %ss", self.timeout)
            return ProviderResult(
                provider=self.name,
                verdict=Verdict.ERROR,
                details=f"Timeout / Unavailable (no response within {self.timeout}s)",
            )
        except requests.RequestException as exc:
            logger.error("ThreatFox request failed: %s", exc)
            return ProviderResult(
                provider=self.name,
                verdict=Verdict.ERROR,
                details=f"Request failed: {exc}",
            )
        except (KeyError, TypeError, ValueError) as exc:
            logger.error("ThreatFox parse error: %s", exc)
            return ProviderResult(
                provider=self.name,
                verdict=Verdict.ERROR,
                details="Unexpected response format",
            )

    def lookup_ip(self, ioc: str) -> ProviderResult:
        try:
            ipaddress.IPv4Address(ioc)
        except ValueError:
            return self._invalid_input(ioc, "not a valid IPv4 address")
        return self._search_ioc(ioc)

    def lookup_domain(self, ioc: str) -> ProviderResult:
        if not is_valid_domain(ioc):
            return self._invalid_input(ioc, "not a valid domain (no recognized TLD)")
        return self._search_ioc(ioc)

    def lookup_url(self, ioc: str) -> ProviderResult:
        try:
            parsed = urlparse(ioc)
        except ValueError:
            parsed = None
        if not parsed or not parsed.scheme or not parsed.netloc:
            return self._invalid_input(ioc, "malformed URL")
        return self._search_ioc(ioc)

    def lookup_hash(self, ioc: str) -> ProviderResult:
        pattern = _HASH_RE.get(len(ioc))
        if pattern is None or not pattern.match(ioc):
            return self._invalid_input(ioc, "not a valid MD5/SHA1/SHA256 hash")
        return self._search_ioc(ioc)
