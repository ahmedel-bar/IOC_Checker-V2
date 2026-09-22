"""
providers/otx.py

AlienVault OTX (Open Threat Exchange) provider.

Docs: https://otx.alienvault.com/api

Each lookup method validates its input's shape before making any request
- this is defense-in-depth: extraction should never hand OTX something
malformed (see artifacts/_scan.py and domain_validation.py), but
validating here too means a bad value can never reach the API and
produce an avoidable HTTP 400 regardless of how it got here (a future
extractor, a bug elsewhere, direct programmatic use of this provider,
etc).

OTX's default timeout is intentionally higher than most other providers
(30s vs the project default of 15s) - OTX has historically been prone to
slow responses that read-timeout at 15s under normal load, and 30s gives
genuinely slow-but-working requests room to complete while still being a
firm, finite bound (never unbounded).
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

BASE_URL = "https://otx.alienvault.com/api/v1/indicators"

# OTX-specific default timeout - see module docstring.
DEFAULT_TIMEOUT = 30

_HASH_RE = {
    32: re.compile(r"^[a-fA-F0-9]{32}$"),
    40: re.compile(r"^[a-fA-F0-9]{40}$"),
    64: re.compile(r"^[a-fA-F0-9]{64}$"),
}


class OTXProvider(BaseProvider):
    name = "AlienVault OTX"
    SUPPORTED_TYPES = {
        IOCType.IPV4,
        IOCType.DOMAIN,
        IOCType.URL,
        IOCType.MD5,
        IOCType.SHA1,
        IOCType.SHA256,
    }
    # See module docstring - OTX specifically benefits from a longer
    # timeout than the project default. providers.manager looks this up
    # generically via getattr, so no special-casing is needed anywhere
    # else; any future provider can opt into its own override the same way.
    DEFAULT_TIMEOUT = DEFAULT_TIMEOUT

    def __init__(self, api_key: str | None, timeout: int = DEFAULT_TIMEOUT) -> None:
        self.api_key = api_key
        self.timeout = timeout

    def _headers(self) -> dict:
        return {"X-OTX-API-KEY": self.api_key or ""}

    def _not_configured(self) -> ProviderResult:
        return ProviderResult(
            provider=self.name,
            verdict=Verdict.ERROR,
            details="API key not configured",
        )

    def _invalid_input(self, ioc: str, reason: str) -> ProviderResult:
        """
        Return an ERROR result without making any request. Used when the
        supplied value doesn't actually look like the IOC type it's
        claimed to be - this is what stops something like "wp-cron.php"
        from ever reaching /indicators/domain/wp-cron.php/general and
        producing an avoidable HTTP 400.
        """
        logger.warning("%s skipping invalid value %r: %s", self.name, ioc, reason)
        return ProviderResult(
            provider=self.name,
            verdict=Verdict.ERROR,
            details=f"Skipped - {reason}",
        )

    def _safe_lookup(self, path: str) -> ProviderResult:
        if not self.api_key:
            return self._not_configured()
        try:
            response = request_with_retry(
                lambda: requests.get(
                    f"{BASE_URL}{path}/general",
                    headers=self._headers(),
                    timeout=self.timeout,
                ),
                self.name,
            )
            if response.status_code == 404:
                return ProviderResult(
                    provider=self.name,
                    verdict=Verdict.NOT_FOUND,
                    details="No report found",
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
            pulse_count = data.get("pulse_info", {}).get("count", 0)

            if pulse_count > 0:
                verdict = Verdict.MALICIOUS
                risk = 30
                details = f"Threat Pulses: {pulse_count}"
            else:
                verdict = Verdict.CLEAN
                risk = 0
                details = "No Threat Pulses Found"

            return ProviderResult(
                provider=self.name,
                verdict=verdict,
                details=details,
                risk_contribution=risk,
                raw=data,
            )
        except requests.Timeout:
            logger.error("OTX request timed out after %ss", self.timeout)
            return ProviderResult(
                provider=self.name,
                verdict=Verdict.ERROR,
                details=f"Timeout / Unavailable (no response within {self.timeout}s)",
            )
        except requests.RequestException as exc:
            logger.error("OTX request failed: %s", exc)
            return ProviderResult(
                provider=self.name,
                verdict=Verdict.ERROR,
                details=f"Request failed: {exc}",
            )
        except (KeyError, TypeError, ValueError) as exc:
            logger.error("OTX parse error: %s", exc)
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
        return self._safe_lookup(f"/IPv4/{ioc}")

    def lookup_domain(self, ioc: str) -> ProviderResult:
        if not is_valid_domain(ioc):
            return self._invalid_input(ioc, "not a valid domain (no recognized TLD)")
        return self._safe_lookup(f"/domain/{ioc}")

    def lookup_url(self, ioc: str) -> ProviderResult:
        try:
            parsed = urlparse(ioc)
        except ValueError:
            return self._invalid_input(ioc, "malformed URL")
        if not parsed.scheme or not parsed.netloc:
            return self._invalid_input(ioc, "malformed URL")

        # OTX expects the raw URL as a path-encoded parameter via its "url" endpoint.
        try:
            import urllib.parse

            encoded = urllib.parse.quote(ioc, safe="")
            return self._safe_lookup(f"/url/{encoded}")
        except Exception as exc:  # noqa: BLE001
            logger.error("OTX URL encoding failed: %s", exc)
            return ProviderResult(
                provider=self.name, verdict=Verdict.ERROR, details=str(exc)
            )

    def lookup_hash(self, ioc: str) -> ProviderResult:
        pattern = _HASH_RE.get(len(ioc))
        if pattern is None or not pattern.match(ioc):
            return self._invalid_input(ioc, "not a valid MD5/SHA1/SHA256 hash")
        return self._safe_lookup(f"/file/{ioc}")
