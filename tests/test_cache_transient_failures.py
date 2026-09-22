"""
tests/test_cache_transient_failures.py

Cacheability of ProviderResult objects (cache/cache.py's
is_cacheable_result): only results that represent a real reputation
result about the IOC (CLEAN/MALICIOUS/SUSPICIOUS/FOUND/NOT_FOUND) may be
persisted and reused. Anything describing the provider/API's execution
state instead (RATE_LIMITED, any flavor of ERROR - timeout, HTTP 5xx,
connection failure, missing API key, permanent input rejection - or
UNSUPPORTED) must never be cached, so a transient failure from one run
can never be silently served back as a "result" in a later run.
"""

from __future__ import annotations

import sqlite3
import time

from cache.cache import IOCCache, is_cacheable_result
from utils import ProviderResult, Verdict


def _cache(tmp_path, ttl_seconds=3600):
    return IOCCache(db_path=str(tmp_path / "cache.db"), ttl_seconds=ttl_seconds)


# --- Provider/API execution states are never cached ----------------------

def test_timeout_not_cached(tmp_path):
    cache = _cache(tmp_path)
    result = ProviderResult(
        provider="AlienVault OTX",
        verdict=Verdict.ERROR,
        details="Timeout / Unavailable (no response within 30s)",
    )
    cache.set("evil.example.com", "Domain", "AlienVault OTX", result)
    assert cache.get("evil.example.com", "Domain", "AlienVault OTX") is None


def test_http_5xx_not_cached(tmp_path):
    cache = _cache(tmp_path)
    for code in (500, 502, 503, 504):
        result = ProviderResult(
            provider="AlienVault OTX", verdict=Verdict.ERROR, details=f"Unavailable (HTTP {code})"
        )
        cache.set(f"flaky{code}.example.com", "Domain", "AlienVault OTX", result)
        assert cache.get(f"flaky{code}.example.com", "Domain", "AlienVault OTX") is None


def test_connection_error_not_cached(tmp_path):
    cache = _cache(tmp_path)
    result = ProviderResult(
        provider="VirusTotal", verdict=Verdict.ERROR, details="Request failed: Connection aborted."
    )
    cache.set("unreachable.example.com", "Domain", "VirusTotal", result)
    assert cache.get("unreachable.example.com", "Domain", "VirusTotal") is None


def test_http_401_authentication_failure_not_cached(tmp_path):
    cache = _cache(tmp_path)
    result = ProviderResult(provider="ThreatFox", verdict=Verdict.ERROR, details="Unavailable (HTTP 401)")
    cache.set("locked-out.example.com", "Domain", "ThreatFox", result)
    assert cache.get("locked-out.example.com", "Domain", "ThreatFox") is None


def test_api_key_not_configured_not_cached(tmp_path):
    """
    The bug this fix addresses: "API key not configured" doesn't contain
    any of the old marker substrings ("timeout", "unavailable",
    "connection", "request failed"), so it used to slip through and get
    cached as if it were a real result. It must not, going forward.
    """
    cache = _cache(tmp_path)
    result = ProviderResult(provider="VirusTotal", verdict=Verdict.ERROR, details="API key not configured")
    cache.set("8.8.8.8", "IPv4", "VirusTotal", result)
    assert cache.get("8.8.8.8", "IPv4", "VirusTotal") is None


def test_rate_limited_never_cached(tmp_path):
    """
    The other half of the bug this fix addresses: RATE_LIMITED is a
    different Verdict from ERROR entirely, so the old details-text check
    (which only ever looked at ERROR results) never touched it - it was
    always cached. A rate-limited response describes the provider's
    state at request time, not the IOC's reputation, so it must never be
    persisted as a reusable result.
    """
    cache = _cache(tmp_path)
    result = ProviderResult(
        provider="VirusTotal", verdict=Verdict.RATE_LIMITED,
        details="Rate limit exceeded - request skipped, try again later",
    )
    cache.set("busy.example.com", "Domain", "VirusTotal", result)
    assert cache.get("busy.example.com", "Domain", "VirusTotal") is None


def test_invalid_domain_rejection_not_cached(tmp_path):
    """
    A permanent, deterministic input rejection is still an ERROR
    verdict, and is therefore excluded like every other ERROR - it costs
    nothing to redo (it's a local, offline check with no network call),
    so there's no benefit to caching it and doing so would blur the line
    between "provider execution state" and "reputation result".
    """
    cache = _cache(tmp_path)
    result = ProviderResult(
        provider="AlienVault OTX", verdict=Verdict.ERROR,
        details="Skipped - not a valid domain (no recognized TLD)",
    )
    cache.set("wp-cron.php", "Domain", "AlienVault OTX", result)
    assert cache.get("wp-cron.php", "Domain", "AlienVault OTX") is None


def test_http_400_not_cached(tmp_path):
    cache = _cache(tmp_path)
    result = ProviderResult(provider="VirusTotal", verdict=Verdict.ERROR, details="Invalid Request (HTTP 400)")
    cache.set("weird-value", "Domain", "VirusTotal", result)
    assert cache.get("weird-value", "Domain", "VirusTotal") is None


def test_unsupported_not_cached(tmp_path):
    cache = _cache(tmp_path)
    result = ProviderResult(
        provider="AbuseIPDB", verdict=Verdict.UNSUPPORTED, details="AbuseIPDB only supports IPv4 lookups"
    )
    cache.set("evil.example.com", "Domain", "AbuseIPDB", result)
    assert cache.get("evil.example.com", "Domain", "AbuseIPDB") is None


# --- Real reputation results are still cached, unaffected -----------------

def test_clean_verdict_still_cached(tmp_path):
    cache = _cache(tmp_path)
    result = ProviderResult(provider="VirusTotal", verdict=Verdict.CLEAN, details="0/74 detections (0.0%)")
    cache.set("safe.example.com", "Domain", "VirusTotal", result)
    cached = cache.get("safe.example.com", "Domain", "VirusTotal")
    assert cached is not None
    assert cached.verdict == Verdict.CLEAN


def test_malicious_verdict_still_cached(tmp_path):
    cache = _cache(tmp_path)
    result = ProviderResult(provider="AlienVault OTX", verdict=Verdict.MALICIOUS, details="Threat Pulses: 5", risk_contribution=30)
    cache.set("evil.example.com", "Domain", "AlienVault OTX", result)
    cached = cache.get("evil.example.com", "Domain", "AlienVault OTX")
    assert cached is not None
    assert cached.verdict == Verdict.MALICIOUS


def test_suspicious_verdict_still_cached(tmp_path):
    cache = _cache(tmp_path)
    result = ProviderResult(provider="VirusTotal", verdict=Verdict.SUSPICIOUS, details="2/74 detections (2.7%)")
    cache.set("maybe.example.com", "Domain", "VirusTotal", result)
    cached = cache.get("maybe.example.com", "Domain", "VirusTotal")
    assert cached is not None
    assert cached.verdict == Verdict.SUSPICIOUS


def test_found_verdict_still_cached(tmp_path):
    cache = _cache(tmp_path)
    result = ProviderResult(provider="ThreatFox", verdict=Verdict.FOUND, details="Malware Family: Cobalt Strike", risk_contribution=30)
    cache.set("87.96.21.84", "IPv4", "ThreatFox", result)
    cached = cache.get("87.96.21.84", "IPv4", "ThreatFox")
    assert cached is not None
    assert cached.verdict == Verdict.FOUND


def test_not_found_still_cached(tmp_path):
    cache = _cache(tmp_path)
    result = ProviderResult(provider="MalwareBazaar", verdict=Verdict.NOT_FOUND, details="Hash not found in MalwareBazaar")
    cache.set("abc123", "SHA256", "MalwareBazaar", result)
    assert cache.get("abc123", "SHA256", "MalwareBazaar") is not None


def test_threatfox_illegal_search_term_result_still_cached(tmp_path):
    """
    ThreatFox now normalizes query_status == "illegal_search_term" to a
    plain NOT_FOUND (see providers/threatfox.py) rather than ERROR, so
    it's cached exactly like any other NOT_FOUND result - no special
    casing needed here.
    """
    cache = _cache(tmp_path)
    result = ProviderResult(provider="ThreatFox", verdict=Verdict.NOT_FOUND, details="No match found")
    cache.set("ctldl.windowsupdate.com", "Domain", "ThreatFox", result)
    assert cache.get("ctldl.windowsupdate.com", "Domain", "ThreatFox") is not None


# --- is_cacheable_result: direct unit coverage -----------------------------

def test_is_cacheable_result_true_for_every_reputation_verdict():
    for verdict in (Verdict.CLEAN, Verdict.MALICIOUS, Verdict.SUSPICIOUS, Verdict.FOUND, Verdict.NOT_FOUND):
        assert is_cacheable_result(ProviderResult(provider="X", verdict=verdict, details="d")) is True


def test_is_cacheable_result_false_for_every_execution_state_verdict():
    for verdict in (Verdict.RATE_LIMITED, Verdict.ERROR, Verdict.UNSUPPORTED):
        assert is_cacheable_result(ProviderResult(provider="X", verdict=verdict, details="d")) is False


# --- Fresh lookup happens after a non-cacheable result ---------------------

def test_fresh_lookup_possible_after_transient_failure_not_cached(tmp_path):
    """
    The core scenario: a timeout doesn't get cached, so a later set()
    call for the same key with a real result succeeds normally (nothing
    stale is blocking it).
    """
    cache = _cache(tmp_path)
    timeout_result = ProviderResult(
        provider="AlienVault OTX", verdict=Verdict.ERROR,
        details="Timeout / Unavailable (no response within 30s)",
    )
    cache.set("retry-me.example.com", "Domain", "AlienVault OTX", timeout_result)
    assert cache.get("retry-me.example.com", "Domain", "AlienVault OTX") is None

    real_result = ProviderResult(provider="AlienVault OTX", verdict=Verdict.CLEAN, details="No Threat Pulses Found")
    cache.set("retry-me.example.com", "Domain", "AlienVault OTX", real_result)
    cached = cache.get("retry-me.example.com", "Domain", "AlienVault OTX")
    assert cached is not None
    assert cached.verdict == Verdict.CLEAN


def test_fresh_lookup_possible_after_rate_limited_not_cached(tmp_path):
    cache = _cache(tmp_path)
    rate_limited = ProviderResult(
        provider="VirusTotal", verdict=Verdict.RATE_LIMITED, details="Rate limit exceeded"
    )
    cache.set("retry-me-too.example.com", "Domain", "VirusTotal", rate_limited)
    assert cache.get("retry-me-too.example.com", "Domain", "VirusTotal") is None

    real_result = ProviderResult(provider="VirusTotal", verdict=Verdict.MALICIOUS, details="9/74", risk_contribution=40)
    cache.set("retry-me-too.example.com", "Domain", "VirusTotal", real_result)
    cached = cache.get("retry-me-too.example.com", "Domain", "VirusTotal")
    assert cached is not None
    assert cached.verdict == Verdict.MALICIOUS


# --- Old pre-existing database rows are rejected on read -------------------
#
# These bypass IOCCache.set() entirely and write directly to the SQLite
# file, simulating rows a previous version of this cache (before this
# fix) might have already persisted. The read path must reject them
# exactly as if set() had refused to write them today - no migration or
# schema change, no deleting the .db file.

def _write_raw_row(db_path, ioc, ioc_type, provider, status, details, risk_contribution=0):
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "INSERT OR REPLACE INTO ioc_cache "
        "(ioc, ioc_type, provider, status, result, risk_contribution, timestamp) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (ioc, ioc_type, provider, status, details, risk_contribution, time.time()),
    )
    conn.commit()
    conn.close()


def test_old_rate_limited_row_rejected_as_cache_hit(tmp_path):
    db_path = tmp_path / "cache.db"
    cache = IOCCache(db_path=str(db_path), ttl_seconds=3600)  # creates the schema
    _write_raw_row(db_path, "old-busy.example.com", "Domain", "VirusTotal", "RATE LIMITED", "stale")

    assert cache.get("old-busy.example.com", "Domain", "VirusTotal") is None


def test_old_error_row_rejected_as_cache_hit(tmp_path):
    db_path = tmp_path / "cache.db"
    cache = IOCCache(db_path=str(db_path), ttl_seconds=3600)
    _write_raw_row(db_path, "old-flaky.example.com", "Domain", "AlienVault OTX", "ERROR", "Unavailable (HTTP 502)")

    assert cache.get("old-flaky.example.com", "Domain", "AlienVault OTX") is None


def test_old_valid_row_still_returned_as_cache_hit(tmp_path):
    """Pre-existing valid reputation data must keep working, unaffected."""
    db_path = tmp_path / "cache.db"
    cache = IOCCache(db_path=str(db_path), ttl_seconds=3600)
    _write_raw_row(db_path, "old-safe.example.com", "Domain", "VirusTotal", "CLEAN", "0/74", risk_contribution=0)

    cached = cache.get("old-safe.example.com", "Domain", "VirusTotal")
    assert cached is not None
    assert cached.verdict == Verdict.CLEAN


# --- Providers remain independent (regression guard for this fix) ---------

def test_multiple_providers_for_same_ioc_stay_independent(tmp_path):
    cache = _cache(tmp_path)
    cache.set("8.8.8.8", "IPv4", "VirusTotal", ProviderResult(provider="VirusTotal", verdict=Verdict.CLEAN, details="vt"))
    cache.set("8.8.8.8", "IPv4", "ThreatFox", ProviderResult(provider="ThreatFox", verdict=Verdict.FOUND, details="tf", risk_contribution=30))
    cache.set("8.8.8.8", "IPv4", "URLhaus", ProviderResult(provider="URLhaus", verdict=Verdict.NOT_FOUND, details="uh"))

    assert cache.get("8.8.8.8", "IPv4", "VirusTotal").verdict == Verdict.CLEAN
    assert cache.get("8.8.8.8", "IPv4", "ThreatFox").verdict == Verdict.FOUND
    assert cache.get("8.8.8.8", "IPv4", "URLhaus").verdict == Verdict.NOT_FOUND


def test_rate_limit_on_one_provider_does_not_affect_another_providers_cache(tmp_path):
    cache = _cache(tmp_path)
    cache.set("8.8.8.8", "IPv4", "VirusTotal", ProviderResult(provider="VirusTotal", verdict=Verdict.RATE_LIMITED, details="busy"))
    cache.set("8.8.8.8", "IPv4", "ThreatFox", ProviderResult(provider="ThreatFox", verdict=Verdict.FOUND, details="tf", risk_contribution=30))

    assert cache.get("8.8.8.8", "IPv4", "VirusTotal") is None
    cached = cache.get("8.8.8.8", "IPv4", "ThreatFox")
    assert cached is not None
    assert cached.verdict == Verdict.FOUND


# --- TTL behavior is unchanged by this fix ---------------------------------

def test_ttl_still_governs_expiry_of_cacheable_entries(tmp_path):
    cache = IOCCache(db_path=str(tmp_path / "cache.db"), ttl_seconds=1)
    result = ProviderResult(provider="OTX", verdict=Verdict.CLEAN, details="No Threat Pulses Found")

    cache.set("evil.com", "Domain", "OTX", result)
    assert cache.get("evil.com", "Domain", "OTX") is not None

    time.sleep(1.5)
    assert cache.get("evil.com", "Domain", "OTX") is None
