"""
providers/http_utils.py

Shared HTTP robustness layer for every provider module: bounded
retry/backoff for rate-limited (HTTP 429) and transient server-error
(502/503/504) responses, explicit verdict helpers so a provider failure
is never silently treated as CLEAN, and a per-run rate-limit circuit
breaker for bulk artifact scans. Used uniformly by every provider
(VirusTotal, OTX, AbuseIPDB, URLhaus, MalwareBazaar, ThreatFox) so this
policy is defined once and can't drift between them.

Design goals:
    - Detect rate limiting (429) and transient server errors
      (502/503/504) explicitly, distinct from a genuine 4xx client
      error (400/401/403/404) which retrying would never fix.
    - Retry a small, bounded number of times with backoff - never
      indefinitely - so one slow/limited provider can't stall a bulk
      artifact scan involving hundreds or thousands of IOCs.
    - Respect a Retry-After header when the API provides one (capped, in
      case an API returns an unreasonably large value), since that's a
      far better signal than a guessed backoff interval.
    - On final failure, return the last response rather than raising, so
      the calling provider can distinguish rate-limited / unavailable /
      other failure and produce the right Verdict - never CLEAN or
      MALICIOUS on the strength of a failed request.
    - Provide one place (RateLimitTracker) that remembers "this provider
      is rate-limited for the rest of this run" across many IOCs, so a
      bulk scan doesn't repeat the same doomed request-and-retry
      sequence hundreds of times once a provider's limit is hit.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Callable

import requests

logger = logging.getLogger("ioc_checker")

RATE_LIMIT_STATUS = 429
# Server-side errors worth a short retry: the request itself was fine,
# the provider's infrastructure had a transient problem. 400/401/403/404
# are deliberately NOT in this set - retrying an invalid/unauthorized/
# not-found request just repeats the same failure.
TRANSIENT_SERVER_STATUS_CODES = {502, 503, 504}

# Bounded retry policy: at most this many *extra* attempts after the
# first request (MAX_RETRIES=2 means up to 3 total attempts). Kept
# deliberately small and capped - artifact analysis runs many lookups
# concurrently, and a long per-request retry chain would make one
# rate-limited or degraded provider slow down the whole scan rather than
# just reporting itself unavailable and letting the other providers
# proceed.
MAX_RETRIES = 2
BASE_BACKOFF_SECONDS = 1.0
MAX_BACKOFF_SECONDS = 5.0


def is_rate_limited(response: requests.Response) -> bool:
    return response.status_code == RATE_LIMIT_STATUS


def is_transient_server_error(response: requests.Response) -> bool:
    return response.status_code in TRANSIENT_SERVER_STATUS_CODES


def _is_retryable(response: requests.Response) -> bool:
    return is_rate_limited(response) or is_transient_server_error(response)


def _backoff_seconds(response: requests.Response, attempt: int) -> float:
    """
    How long to wait before retrying. Prefers the API's own Retry-After
    header (capped) when present - most relevant for 429s, but harmless
    to honor for a 503 too if a provider sets it; falls back to a short
    exponential backoff otherwise.
    """
    retry_after = response.headers.get("Retry-After")
    if retry_after:
        try:
            return min(float(retry_after), MAX_BACKOFF_SECONDS)
        except ValueError:
            pass
    return min(BASE_BACKOFF_SECONDS * (2 ** attempt), MAX_BACKOFF_SECONDS)


def request_with_retry(
    request_fn: Callable[[], requests.Response],
    provider_name: str,
    max_retries: int = MAX_RETRIES,
) -> requests.Response:
    """
    Call `request_fn()` (a zero-arg callable issuing one HTTP request),
    retrying with backoff if - and only if - the response is rate
    limiting (429) or a transient server error (502/503/504). Any other
    status code (2xx, 3xx, or a genuine 4xx client error) is returned
    immediately without retrying, since retrying those isn't productive.

    Always returns a Response - including a final still-failing response
    after retries are exhausted - rather than raising, so the caller can
    distinguish the failure mode and produce the right Verdict instead of
    a generic ERROR.

    `request_fn` itself is expected to let requests.RequestException
    (connection errors, read timeouts) propagate - those are handled by
    each provider's own try/except around this call, consistent with how
    every provider already handles network-level failures.
    """
    response = request_fn()

    attempt = 0
    while _is_retryable(response) and attempt < max_retries:
        delay = _backoff_seconds(response, attempt)
        reason = "rate limited (HTTP 429)" if is_rate_limited(response) else f"HTTP {response.status_code}"
        logger.warning(
            "%s %s, retrying in %.1fs (attempt %d/%d)",
            provider_name,
            reason,
            delay,
            attempt + 1,
            max_retries,
        )
        time.sleep(delay)
        response = request_fn()
        attempt += 1

    return response


class RateLimitTracker:
    """
    Thread-safe, per-run circuit breaker for rate-limited providers.

    The bounded retry above (request_with_retry) handles a single
    request being rate-limited. This class handles the bulk-scan case:
    once a provider has been confirmed rate-limited during the current
    artifact analysis run, there's no value in every remaining IOC
    repeating the same doomed request-and-retry sequence against it -
    that's exactly what produced things like "VirusTotal rate limited
    (x33)" in a single run. Once marked, lookups against that provider
    are skipped immediately (no network call at all) for the rest of
    this run, while every other provider continues normally.

    Scoped to a single analysis run - a fresh instance is created per
    `analyze_artifact()` call, so a provider being marked here has no
    effect on any other run (each invocation of the CLI gets a clean
    slate; this is independent of and does not change the disk cache's
    TTL-based behavior).
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._limited_providers: set[str] = set()

    def is_limited(self, provider_name: str) -> bool:
        with self._lock:
            return provider_name in self._limited_providers

    def mark_limited(self, provider_name: str) -> None:
        with self._lock:
            if provider_name not in self._limited_providers:
                logger.warning(
                    "%s rate limited - skipping further requests to it for the rest of this run",
                    provider_name,
                )
            self._limited_providers.add(provider_name)
