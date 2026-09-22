"""
tests/test_artifact_pipeline_url_children.py

End-to-end test of the URL -> host parent/child feature through the full
artifact analysis pipeline (extraction -> derivation -> aggregation ->
lookup -> report rows), with every provider network call mocked out.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import patch

from artifact_pipeline import analyze_artifact
from cache.cache import IOCCache
from config import AppConfig, ProviderConfig
from detector import IOCType
from utils import ProviderResult, Verdict


def _config() -> AppConfig:
    return AppConfig(
        virustotal=ProviderConfig(display_name="VirusTotal", env_var="VT_API_KEY", api_key="dummy"),
        otx=ProviderConfig(display_name="AlienVault OTX", env_var="OTX_API_KEY", api_key="dummy"),
        threatfox=ProviderConfig(display_name="ThreatFox", env_var="THREATFOX_API_KEY", api_key="dummy"),
        abuseipdb=ProviderConfig(display_name="AbuseIPDB", env_var="ABUSEIPDB_API_KEY", api_key="dummy"),
        urlhaus=ProviderConfig(display_name="URLhaus", env_var="URLHAUS_API_KEY", api_key=None, requires_key=False),
        malwarebazaar=ProviderConfig(
            display_name="MalwareBazaar", env_var="MALWAREBAZAAR_API_KEY", api_key=None, requires_key=False
        ),
    )


def _fake_query_provider(malicious_ip: str):
    def _query(provider, method_name, ioc):
        if ioc == malicious_ip:
            return ProviderResult(provider=provider.name, verdict=Verdict.MALICIOUS, details="bad", risk_contribution=50)
        return ProviderResult(provider=provider.name, verdict=Verdict.NOT_FOUND, details="No match found")

    return _query


def _run(text: str, malicious_ip: str = ""):
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "artifact.txt"
        path.write_text(text)
        cache = IOCCache(db_path=str(Path(tmp) / "cache.sqlite3"))
        with patch("artifact_pipeline.query_provider", side_effect=_fake_query_provider(malicious_ip)):
            rows, summary = analyze_artifact(str(path), _config(), cache)
    return rows, summary


def test_url_with_ipv4_host_creates_independent_parent_and_child_rows():
    rows, _ = _run("http://87.96.21.84/Invoke-SMBExec.ps1")
    by_key = {(r.ioc, r.ioc_type): r for r in rows}

    url_row = by_key[("http://87.96.21.84/Invoke-SMBExec.ps1", IOCType.URL)]
    ip_row = by_key[("87.96.21.84", IOCType.IPV4)]

    assert url_row.parent is None
    assert ip_row.parent == "http://87.96.21.84/Invoke-SMBExec.ps1"


def test_url_with_domain_host_creates_independent_parent_and_child_rows():
    rows, _ = _run("http://example.com/malware.exe")
    by_key = {(r.ioc, r.ioc_type): r for r in rows}

    url_row = by_key[("http://example.com/malware.exe", IOCType.URL)]
    domain_row = by_key[("example.com", IOCType.DOMAIN)]

    assert url_row.parent is None
    assert domain_row.parent == "http://example.com/malware.exe"


def test_repeated_urls_with_same_ip_produce_one_child_and_one_set_of_lookups():
    text = (
        "http://87.96.21.84/a.exe\n"
        "http://87.96.21.84/b.exe\n"
        "http://87.96.21.84/c.exe\n"
    )
    call_log = []

    def _query(provider, method_name, ioc):
        call_log.append((provider.name, ioc))
        return ProviderResult(provider=provider.name, verdict=Verdict.NOT_FOUND, details="No match found")

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "artifact.txt"
        path.write_text(text)
        cache = IOCCache(db_path=str(Path(tmp) / "cache.sqlite3"))
        with patch("artifact_pipeline.query_provider", side_effect=_query):
            rows, _ = analyze_artifact(str(path), _config(), cache)

    ip_rows = [r for r in rows if r.ioc_type == IOCType.IPV4]
    assert len(ip_rows) == 1
    assert ip_rows[0].occurrences == 3

    # Exactly one lookup per (provider, "87.96.21.84") pair - never three.
    ip_calls = [c for c in call_log if c[1] == "87.96.21.84"]
    assert len(ip_calls) == len(set(ip_calls))


def test_child_ip_reputation_is_independent_of_clean_parent_url():
    rows, _ = _run("http://87.96.21.84/Invoke-SMBExec.ps1", malicious_ip="87.96.21.84")
    by_key = {(r.ioc, r.ioc_type): r for r in rows}

    url_row = by_key[("http://87.96.21.84/Invoke-SMBExec.ps1", IOCType.URL)]
    ip_row = by_key[("87.96.21.84", IOCType.IPV4)]

    assert url_row.classification == "CLEAN"
    assert ip_row.classification != "CLEAN"
    assert ip_row.hit_count > 0


def test_malformed_hostname_produces_no_child_row():
    rows, _ = _run("http://[::1]/beacon")
    assert len(rows) == 1
    assert rows[0].ioc_type == IOCType.URL
    assert rows[0].parent is None
