"""
providers/abuseipdb.py

AbuseIPDB provider. Requires an API key.

Docs: https://docs.abuseipdb.com/
Only supports IPv4 lookups.
"""

from __future__ import annotations

import ipaddress
import logging

import requests

from detector import IOCType
from providers import BaseProvider
from providers.http_utils import is_rate_limited, request_with_retry
from utils import ProviderResult, Verdict

logger = logging.getLogger("ioc_checker")

API_URL = "https://api.abuseipdb.com/api/v2/check"


class AbuseIPDBProvider(BaseProvider):
    name = "AbuseIPDB"
    SUPPORTED_TYPES = {IOCType.IPV4}

    def __init__(self, api_key: str | None, timeout: int = 15) -> None:
        self.api_key = api_key
        self.timeout = timeout

    def _headers(self) -> dict:
        return {"Key": self.api_key or "", "Accept": "application/json"}

    def _not_configured(self) -> ProviderResult:
        return ProviderResult(
            provider=self.name,
            verdict=Verdict.ERROR,
            details="API key not configured",
        )

    def _unsupported(self) -> ProviderResult:
        return ProviderResult(
            provider=self.name,
            verdict=Verdict.UNSUPPORTED,
            details="AbuseIPDB only supports IPv4 lookups",
        )

    def lookup_ip(self, ioc: str) -> ProviderResult:
        if not self.api_key:
            return self._not_configured()
        try:
            ipaddress.IPv4Address(ioc)
        except ValueError:
            logger.warning("AbuseIPDB skipping invalid IPv4 value %r", ioc)
            return ProviderResult(
                provider=self.name,
                verdict=Verdict.ERROR,
                details="Skipped - not a valid IPv4 address",
            )
        try:
            response = request_with_retry(
                lambda: requests.get(
                    API_URL,
                    headers=self._headers(),
                    params={"ipAddress": ioc, "maxAgeInDays": 90},
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

            payload = response.json()
            data = payload.get("data", {})

            score = data.get("abuseConfidenceScore", 0)
            country = data.get("countryCode") or "Unknown"
            isp = data.get("isp") or "Unknown"
            total_reports = data.get("totalReports", 0)

            # Verdict tiers.
            #
            # AbuseIPDB's own guidance is that a confidence score of 75-100 is
            # the actionable "block" range, and it recommends against treating
            # the low end (below ~25) as malicious. But a nonzero score that is
            # backed by real community reports is not the same as a pristine IP
            # with a 0 score and no reports - calling that "CLEAN" is
            # misleading. We therefore separate three cases:
            #
            #   score >= 75                        -> MALICIOUS (strong signal)
            #   score >= 25                        -> SUSPICIOUS (elevated)
            #   0 < score < 25 AND has reports     -> SUSPICIOUS (low, but flagged)
            #   score == 0, or no reports at all   -> CLEAN
            #
            # This keeps genuinely-uncontested IPs CLEAN while ensuring an IP
            # with, say, a 16% score and 2 reports is surfaced as low-level
            # suspicious rather than silently marked clean.
            if score >= 75:
                verdict = Verdict.MALICIOUS
                risk = 40
                reason = "High abuse confidence"
            elif score >= 25:
                verdict = Verdict.SUSPICIOUS
                risk = 20
                reason = "Elevated abuse confidence"
            elif score > 0 and total_reports > 0:
                verdict = Verdict.SUSPICIOUS
                risk = 10
                reason = "Low confidence, but community reports exist"
            else:
                verdict = Verdict.CLEAN
                risk = 0
                reason = "No abuse reports" if total_reports == 0 else "Negligible abuse confidence"

            details = (
                f"Abuse Confidence Score: {score}%\n"
                f"Country: {country}\n"
                f"ISP: {isp}\n"
                f"Total Reports: {total_reports}\n"
                f"Assessment: {reason}\n"
                f"Confidence: {score}%"
            )

            return ProviderResult(
                provider=self.name,
                verdict=verdict,
                details=details,
                risk_contribution=risk,
                raw=payload,
            )
        except requests.Timeout:
            logger.error("AbuseIPDB request timed out after %ss", self.timeout)
            return ProviderResult(
                provider=self.name,
                verdict=Verdict.ERROR,
                details=f"Timeout / Unavailable (no response within {self.timeout}s)",
            )
        except requests.RequestException as exc:
            logger.error("AbuseIPDB request failed: %s", exc)
            return ProviderResult(
                provider=self.name,
                verdict=Verdict.ERROR,
                details=f"Request failed: {exc}",
            )
        except (KeyError, TypeError, ValueError) as exc:
            logger.error("AbuseIPDB parse error: %s", exc)
            return ProviderResult(
                provider=self.name,
                verdict=Verdict.ERROR,
                details="Unexpected response format",
            )

    def lookup_domain(self, ioc: str) -> ProviderResult:
        return self._unsupported()

    def lookup_url(self, ioc: str) -> ProviderResult:
        return self._unsupported()

    def lookup_hash(self, ioc: str) -> ProviderResult:
        return self._unsupported()
