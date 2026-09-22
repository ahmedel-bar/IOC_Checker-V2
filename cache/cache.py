"""
cache/cache.py

Lightweight SQLite-backed cache for provider lookup results, keyed by
(ioc, ioc_type, provider). Used exclusively by the artifact analysis
pipeline to avoid repeating the same API call across analysis runs (the
in-run deduplication in ioc/aggregator.py already ensures an IOC is only
looked up once *within* a single run; this cache extends that guarantee
*across* runs).

SQLite was chosen specifically because it's part of the Python standard
library - no new dependency, no server process, and it's more than
sufficient for what is fundamentally a small key-value store with a TTL.

Entries older than the configured TTL are treated as a cache miss and
transparently re-fetched (and overwritten) rather than being served stale
forever.

Cacheability - what belongs in this cache and what doesn't - is decided
generically from a result's Verdict alone (see is_cacheable_result
below), never from provider identity or a details-text pattern. This
keeps every current and future provider covered by the same rule
automatically, with zero provider-specific logic in this module.

The distinction that matters is:

    1. IOC reputation result - what a provider found out about the IOC
       itself (CLEAN, MALICIOUS, SUSPICIOUS, FOUND, NOT_FOUND). This is a
       fact about the IOC and is safe to reuse for the rest of the TTL.

    2. Provider/API execution state - what happened when we tried to ask
       (rate-limited, unavailable, timed out, connection failed,
       authentication/config failure, or any other request-level
       problem). This describes the *request*, not the IOC, and trying
       again might get a completely different answer - caching it would
       "lock in" that failure and silently serve it back on a later run
       as if it were a fresh, current result. Every one of these
       currently comes back as Verdict.RATE_LIMITED or Verdict.ERROR
       (see providers/*.py), so excluding those two verdicts from the
       cache is what keeps every provider/failure-mode covered without
       needing to know provider-specific details text.

Verdict.UNSUPPORTED (a provider declaring it doesn't handle a given IOC
type at all) is likewise excluded - it isn't a reputation result either,
though in practice it's never reached through the normal pipeline anyway
(providers.manager.get_providers_for_type already only selects providers
that support the IOC type being looked up).
"""

from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path

from utils import ProviderResult, Verdict

DEFAULT_TTL_SECONDS = 6 * 60 * 60  # 6 hours

# The only verdicts that represent an actual reputation result about the
# IOC itself, as opposed to a provider/API execution state (see module
# docstring). Deliberately generic and verdict-only - no provider name
# and no details-text pattern is ever consulted here, so every current
# and future provider is covered automatically by the same rule.
_CACHEABLE_VERDICTS = {
    Verdict.CLEAN,
    Verdict.MALICIOUS,
    Verdict.SUSPICIOUS,
    Verdict.FOUND,
    Verdict.NOT_FOUND,
}


def is_cacheable_result(result: ProviderResult) -> bool:
    """
    True if `result` represents a real reputation result about the IOC
    (CLEAN/MALICIOUS/SUSPICIOUS/FOUND/NOT_FOUND) and is therefore safe to
    persist and reuse for the rest of the cache TTL.

    False for anything that instead describes the provider/API's state
    at request time rather than the IOC's reputation - RATE_LIMITED,
    every flavor of ERROR (timeout, HTTP 5xx/unavailable, connection
    failure, authentication failure, missing API key, or any other
    request-level problem), and UNSUPPORTED. Trying again later might
    get a completely different answer for these, so persisting them
    would incorrectly "lock in" a transient state as if it were settled
    reputation data.
    """
    return result.verdict in _CACHEABLE_VERDICTS


class IOCCache:
    """Thread-safe SQLite cache for ProviderResult objects with TTL expiry."""

    def __init__(self, db_path: str = "ioc_cache.db", ttl_seconds: int = DEFAULT_TTL_SECONDS) -> None:
        self.db_path = db_path
        self.ttl_seconds = ttl_seconds
        self._lock = threading.Lock()
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path, check_same_thread=False)

    def _init_db(self) -> None:
        parent = Path(self.db_path).parent
        if str(parent) not in ("", "."):
            parent.mkdir(parents=True, exist_ok=True)
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS ioc_cache (
                    ioc TEXT NOT NULL,
                    ioc_type TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    status TEXT NOT NULL,
                    result TEXT NOT NULL,
                    risk_contribution INTEGER NOT NULL DEFAULT 0,
                    timestamp REAL NOT NULL,
                    PRIMARY KEY (ioc, ioc_type, provider)
                )
                """
            )

    def get(self, ioc: str, ioc_type: str, provider: str) -> ProviderResult | None:
        """
        Return a cached ProviderResult if present, not expired, and it
        represents a real reputation result - else None (a cache miss).

        The last check is what protects against old rows written before
        this cacheability rule existed (or written by an older version
        of this module): a stored RATE_LIMITED/ERROR/UNSUPPORTED status
        is rejected here exactly like a fresh one would be by set()
        below, so a stale transient-failure row already sitting in the
        database can never come back as a cache hit - the caller is left
        free to perform a fresh lookup, per the project's existing
        provider logic, with no schema change or migration needed.
        """
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT status, result, risk_contribution, timestamp "
                "FROM ioc_cache WHERE ioc = ? AND ioc_type = ? AND provider = ?",
                (ioc, ioc_type, provider),
            ).fetchone()

        if row is None:
            return None

        status, details, risk_contribution, timestamp = row
        if time.time() - timestamp > self.ttl_seconds:
            return None  # expired - treated as a cache miss, will be overwritten on next set()

        try:
            verdict = Verdict(status)
        except ValueError:
            return None  # corrupted/unknown status value - safest to treat as a miss

        result = ProviderResult(
            provider=provider,
            verdict=verdict,
            details=details,
            risk_contribution=risk_contribution,
        )

        if not is_cacheable_result(result):
            # A transient provider/API state (possibly written by an
            # older build of this cache, before this rule existed) - not
            # a valid reusable reputation result. Treat exactly like a
            # miss rather than serving it back.
            return None

        return result

    def set(self, ioc: str, ioc_type: str, provider: str, result: ProviderResult) -> None:
        """
        Store (or overwrite) a ProviderResult in the cache - unless it
        represents a transient provider/API state (RATE_LIMITED, or any
        flavor of ERROR/UNSUPPORTED) rather than an actual reputation
        result, in which case it's deliberately never persisted (see
        is_cacheable_result and the module docstring). Everything else -
        CLEAN/MALICIOUS/SUSPICIOUS/FOUND/NOT_FOUND - is cached as before.
        """
        if not is_cacheable_result(result):
            return
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO ioc_cache "
                "(ioc, ioc_type, provider, status, result, risk_contribution, timestamp) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    ioc,
                    ioc_type,
                    provider,
                    result.verdict.value,
                    result.details,
                    result.risk_contribution,
                    time.time(),
                ),
            )

    def purge_expired(self) -> int:
        """Delete expired entries. Returns the number of rows removed."""
        cutoff = time.time() - self.ttl_seconds
        with self._lock, self._connect() as conn:
            cursor = conn.execute("DELETE FROM ioc_cache WHERE timestamp < ?", (cutoff,))
            return cursor.rowcount
