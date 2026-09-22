"""
tests/test_cache.py

SQLite cache: set/get round-trip, cache miss for unknown keys, and TTL
expiry treated as a miss.
"""

from __future__ import annotations

import time

from cache.cache import IOCCache
from utils import ProviderResult, Verdict


def test_cache_hit_after_set(tmp_path):
    cache = IOCCache(db_path=str(tmp_path / "cache.db"), ttl_seconds=60)
    result = ProviderResult(provider="VirusTotal", verdict=Verdict.MALICIOUS, details="5/74", risk_contribution=40)

    cache.set("185.10.20.30", "IPv4", "VirusTotal", result)
    cached = cache.get("185.10.20.30", "IPv4", "VirusTotal")

    assert cached is not None
    assert cached.verdict == Verdict.MALICIOUS
    assert cached.details == "5/74"


def test_cache_miss_for_unknown_key(tmp_path):
    cache = IOCCache(db_path=str(tmp_path / "cache.db"), ttl_seconds=60)
    assert cache.get("8.8.8.8", "IPv4", "VirusTotal") is None


def test_cache_entry_expires_after_ttl(tmp_path):
    cache = IOCCache(db_path=str(tmp_path / "cache.db"), ttl_seconds=1)
    result = ProviderResult(provider="OTX", verdict=Verdict.CLEAN, details="No Threat Pulses Found")

    cache.set("evil.com", "Domain", "OTX", result)
    assert cache.get("evil.com", "Domain", "OTX") is not None

    time.sleep(1.5)
    assert cache.get("evil.com", "Domain", "OTX") is None


def test_cache_keys_are_scoped_by_provider_and_type(tmp_path):
    """The same IOC value must not collide across different providers or types."""
    cache = IOCCache(db_path=str(tmp_path / "cache.db"), ttl_seconds=60)
    r1 = ProviderResult(provider="VirusTotal", verdict=Verdict.MALICIOUS, details="vt")
    r2 = ProviderResult(provider="OTX", verdict=Verdict.CLEAN, details="otx")

    cache.set("evil.com", "Domain", "VirusTotal", r1)
    cache.set("evil.com", "Domain", "OTX", r2)

    assert cache.get("evil.com", "Domain", "VirusTotal").details == "vt"
    assert cache.get("evil.com", "Domain", "OTX").details == "otx"
