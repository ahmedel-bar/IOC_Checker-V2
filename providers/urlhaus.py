"""
providers/urlhaus.py

abuse.ch URLhaus provider. Public API — no API key strictly required,
though an Auth-Key can optionally be supplied for higher rate limits.

Docs: https://urlhaus-api.abuse.ch/

Two distinct endpoints are used, one per IOC shape - URLhaus does not
accept a Domain or IPv4 as a "url" parameter, and does not accept a URL
as a "host" parameter, so each IOC type is routed to its own endpoint
rather than being coerced into the other's shape:

    URL              -> POST /v1/url/   (existing behavior, unchanged)
    Domain / IPv4    -> POST /v1/host/  (new)

The Host endpoint reports whether a given host (domain or IP) has ever
been associated with a malicious URL in URLhaus's database - it returns
a url_count and a list of the associated URLs (each with its own
url_status), rather than a single url_status like the URL endpoint does.
Hashes are not meaningful to either endpoint and remain unsupported.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Callable
from urllib.parse import urlparse

import requests

from detector import IOCType
from domain_validation import is_valid_domain
from providers import BaseProvider
from providers.http_utils import is_rate_limited, request_with_retry
from utils import ProviderResult, Verdict

logger = logging.getLogger("ioc_checker")

URL_API = "https://urlhaus-api.abuse.ch/v1/url/"
HOST_API = "https://urlhaus-api.abuse.ch/v1/host/"


class URLhausProvider(BaseProvider):
    name = "URLhaus"
    SUPPORTED_TYPES = {IOCType.URL, IOCType.DOMAIN, IOCType.IPV4}

    def __init__(self, api_key: str | None, timeout: int = 15) -> None:
        # URLhaus is a public API; the key (if provided) only raises rate limits.
        self.api_key = api_key
        self.timeout = timeout

    def _headers(self) -> dict:
        headers = {}
        if self.api_key:
            headers["Auth-Key"] = self.api_key
        return headers

    def _unsupported(self) -> ProviderResult:
        return ProviderResult(
            provider=self.name,
            verdict=Verdict.UNSUPPORTED,
            details="URLhaus only supports URL, Domain, and IPv4 lookups",
        )

    def _check_common_errors(self, response: requests.Response) -> ProviderResult | None:
        """Shared rate-limit/HTTP-status handling for both endpoints."""
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
        return None

    def _perform_lookup(
        self,
        url: str,
        data: dict,
        parse_fn: Callable[[dict], ProviderResult],
    ) -> ProviderResult:
        """
        Shared request/retry/error-handling flow for both endpoints:
        issue the POST (with rate-limit-aware retry), handle the common
        failure modes (rate limit, non-2xx, timeout, connection error,
        malformed response), and hand a successful JSON payload to
        `parse_fn` for endpoint-specific interpretation.
        """
        try:
            response = request_with_retry(
                lambda: requests.post(
                    url,
                    data=data,
                    headers=self._headers(),
                    timeout=self.timeout,
                ),
                self.name,
            )

            common_error = self._check_common_errors(response)
            if common_error is not None:
                return common_error

            payload = response.json()
            return parse_fn(payload)
        except requests.Timeout:
            logger.error("URLhaus request timed out after %ss", self.timeout)
            return ProviderResult(
                provider=self.name,
                verdict=Verdict.ERROR,
                details=f"Timeout / Unavailable (no response within {self.timeout}s)",
            )
        except requests.RequestException as exc:
            logger.error("URLhaus request failed: %s", exc)
            return ProviderResult(
                provider=self.name,
                verdict=Verdict.ERROR,
                details=f"Request failed: {exc}",
            )
        except (KeyError, TypeError, ValueError) as exc:
            logger.error("URLhaus parse error: %s", exc)
            return ProviderResult(
                provider=self.name,
                verdict=Verdict.ERROR,
                details="Unexpected response format",
            )

    # --- URL lookup: POST /v1/url/ -----------------------------------

    def _parse_url_response(self, data: dict) -> ProviderResult:
        query_status = data.get("query_status")
        if query_status == "no_results":
            return ProviderResult(
                provider=self.name,
                verdict=Verdict.NOT_FOUND,
                details="URL not found in URLhaus",
            )
        if query_status != "ok":
            return ProviderResult(
                provider=self.name,
                verdict=Verdict.ERROR,
                details=f"API status: {query_status}",
            )

        url_status = data.get("url_status", "unknown")
        threat = data.get("threat", "N/A")
        tags = data.get("tags") or []
        tags_str = ", ".join(tags) if tags else "None"

        if url_status == "online":
            verdict = Verdict.MALICIOUS
            risk = 30
            confidence_display = "100%"
        elif url_status == "offline":
            verdict = Verdict.SUSPICIOUS
            risk = 15
            confidence_display = "0%"
        else:
            verdict = Verdict.FOUND
            risk = 15
            confidence_display = "N/A"

        details = (
            f"URL Status: {url_status}\n"
            f"Threat: {threat}\n"
            f"Tags: {tags_str}\n"
            f"Confidence: {confidence_display}"
        )

        return ProviderResult(
            provider=self.name,
            verdict=verdict,
            details=details,
            risk_contribution=risk,
            raw=data,
        )

    def lookup_url(self, ioc: str) -> ProviderResult:
        try:
            parsed = urlparse(ioc)
        except ValueError:
            parsed = None
        if not parsed or not parsed.scheme or not parsed.netloc:
            logger.warning("URLhaus skipping malformed URL %r", ioc)
            return ProviderResult(
                provider=self.name,
                verdict=Verdict.ERROR,
                details="Skipped - malformed URL",
            )

        return self._perform_lookup(URL_API, {"url": ioc}, self._parse_url_response)

    # --- Host lookup: POST /v1/host/ (Domain and IPv4) -----------------

    def _parse_host_response(self, data: dict) -> ProviderResult:
        query_status = data.get("query_status")
        if query_status == "no_results":
            return ProviderResult(
                provider=self.name,
                verdict=Verdict.NOT_FOUND,
                details="Host not found in URLhaus",
            )
        if query_status != "ok":
            return ProviderResult(
                provider=self.name,
                verdict=Verdict.ERROR,
                details=f"API status: {query_status}",
            )

        try:
            url_count = int(data.get("url_count") or 0)
        except (TypeError, ValueError):
            url_count = 0

        urls = data.get("urls") or []
        online_count = sum(1 for entry in urls if entry.get("url_status") == "online")

        firstseen = data.get("firstseen") or "N/A"
        blacklists = data.get("blacklists") or {}
        blacklist_str = (
            ", ".join(f"{name}={status}" for name, status in blacklists.items())
            if blacklists
            else "None"
        )

        if online_count > 0:
            verdict = Verdict.MALICIOUS
            risk = 30
            confidence_display = "100%"
        elif url_count > 0:
            verdict = Verdict.SUSPICIOUS
            risk = 15
            confidence_display = "0%"
        else:
            verdict = Verdict.CLEAN
            risk = 0
            confidence_display = "0%"

        details = (
            f"URL Count: {url_count}\n"
            f"Active Malicious URLs: {online_count}\n"
            f"First Seen: {firstseen}\n"
            f"Blacklists: {blacklist_str}\n"
            f"Confidence: {confidence_display}"
        )

        return ProviderResult(
            provider=self.name,
            verdict=verdict,
            details=details,
            risk_contribution=risk,
            raw=data,
        )

    def lookup_domain(self, ioc: str) -> ProviderResult:
        if not is_valid_domain(ioc):
            logger.warning("URLhaus skipping invalid domain %r", ioc)
            return ProviderResult(
                provider=self.name,
                verdict=Verdict.ERROR,
                details="Skipped - not a valid domain (no recognized TLD)",
            )
        return self._perform_lookup(HOST_API, {"host": ioc}, self._parse_host_response)

    def lookup_ip(self, ioc: str) -> ProviderResult:
        try:
            ipaddress.IPv4Address(ioc)
        except ValueError:
            logger.warning("URLhaus skipping invalid IPv4 value %r", ioc)
            return ProviderResult(
                provider=self.name,
                verdict=Verdict.ERROR,
                details="Skipped - not a valid IPv4 address",
            )
        return self._perform_lookup(HOST_API, {"host": ioc}, self._parse_host_response)

    def lookup_hash(self, ioc: str) -> ProviderResult:
        return self._unsupported()
