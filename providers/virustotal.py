"""
providers/virustotal.py

VirusTotal API v3 provider.

Docs: https://docs.virustotal.com/reference/overview

Each lookup method validates its input's shape before making any request
- defense-in-depth, same reasoning as providers/otx.py and
providers/threatfox.py: extraction and detect_ioc_type() should never
hand VirusTotal something malformed (see domain_validation.py, the
single canonical domain validator shared with detector.py), but
validating here too means a bad value can never produce a request like
/domains/c or /domains/xpaywa regardless of how it got here.
"""

from __future__ import annotations

import base64
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

BASE_URL = "https://www.virustotal.com/api/v3"

_HASH_RE = {
    32: re.compile(r"^[a-fA-F0-9]{32}$"),
    40: re.compile(r"^[a-fA-F0-9]{40}$"),
    64: re.compile(r"^[a-fA-F0-9]{64}$"),
}


class VirusTotalProvider(BaseProvider):
    name = "VirusTotal"
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
        return {"x-apikey": self.api_key or ""}

    def _not_configured(self) -> ProviderResult:
        return ProviderResult(
            provider=self.name,
            verdict=Verdict.ERROR,
            details="API key not configured",
        )

    def _invalid_input(self, ioc: str, reason: str) -> ProviderResult:
        logger.warning("VirusTotal skipping invalid value %r: %s", ioc, reason)
        return ProviderResult(
            provider=self.name,
            verdict=Verdict.ERROR,
            details=f"Skipped - {reason}",
        )

    def _request(self, path: str) -> requests.Response:
        return request_with_retry(
            lambda: requests.get(
                f"{BASE_URL}{path}", headers=self._headers(), timeout=self.timeout
            ),
            self.name,
        )

    def _parse_stats(self, data: dict) -> ProviderResult:
        try:
            attributes = data["data"]["attributes"]
            stats = attributes.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values()) or 1

            if malicious > 0:
                verdict = Verdict.MALICIOUS
                risk = 40
            elif suspicious > 0:
                verdict = Verdict.SUSPICIOUS
                risk = 20
            else:
                verdict = Verdict.CLEAN
                risk = 0

            percentage = (malicious / total) * 100 if total else 0.0
            details = f"{malicious}/{total} detections ({percentage:.1f}%)"
            return ProviderResult(
                provider=self.name,
                verdict=verdict,
                details=details,
                risk_contribution=risk,
                raw=data,
            )
        except (KeyError, TypeError) as exc:
            logger.error("VirusTotal parse error: %s", exc)
            return ProviderResult(
                provider=self.name,
                verdict=Verdict.ERROR,
                details="Unexpected response format",
            )

    def _safe_lookup(self, path: str) -> ProviderResult:
        if not self.api_key:
            return self._not_configured()
        try:
            response = self._request(path)
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
            if response.status_code == 400:
                logger.error("VirusTotal returned HTTP 400 for %s", path)
                return ProviderResult(
                    provider=self.name,
                    verdict=Verdict.ERROR,
                    details="Invalid Request (HTTP 400)",
                )
            if not response.ok:
                return ProviderResult(
                    provider=self.name,
                    verdict=Verdict.ERROR,
                    details=f"Unavailable (HTTP {response.status_code})",
                )
            return self._parse_stats(response.json())
        except requests.Timeout:
            logger.error("VirusTotal request timed out after %ss", self.timeout)
            return ProviderResult(
                provider=self.name,
                verdict=Verdict.ERROR,
                details=f"Timeout / Unavailable (no response within {self.timeout}s)",
            )
        except requests.RequestException as exc:
            logger.error("VirusTotal request failed: %s", exc)
            return ProviderResult(
                provider=self.name,
                verdict=Verdict.ERROR,
                details=f"Request failed: {exc}",
            )

    def lookup_ip(self, ioc: str) -> ProviderResult:
        try:
            ipaddress.IPv4Address(ioc)
        except ValueError:
            return self._invalid_input(ioc, "not a valid IPv4 address")
        return self._safe_lookup(f"/ip_addresses/{ioc}")

    def lookup_domain(self, ioc: str) -> ProviderResult:
        if not is_valid_domain(ioc):
            return self._invalid_input(ioc, "not a valid domain (no recognized TLD)")
        return self._safe_lookup(f"/domains/{ioc}")

    def lookup_url(self, ioc: str) -> ProviderResult:
        if not self.api_key:
            return self._not_configured()
        try:
            parsed = urlparse(ioc)
        except ValueError:
            parsed = None
        if not parsed or not parsed.scheme or not parsed.netloc:
            return self._invalid_input(ioc, "malformed URL")
        url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
        return self._safe_lookup(f"/urls/{url_id}")

    def lookup_hash(self, ioc: str) -> ProviderResult:
        pattern = _HASH_RE.get(len(ioc))
        if pattern is None or not pattern.match(ioc):
            return self._invalid_input(ioc, "not a valid MD5/SHA1/SHA256 hash")
        return self._safe_lookup(f"/files/{ioc}")
