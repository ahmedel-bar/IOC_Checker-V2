"""
tests/test_provider_robustness.py

Provider-layer robustness added this round: every provider validates its
own input before making a request (defense-in-depth beyond the
extraction-layer fix), never classifies a failed/rate-limited/timed-out
request as CLEAN or MALICIOUS, and the shared retry helper handles
transient server errors in addition to rate limiting.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import requests

from providers.abuseipdb import AbuseIPDBProvider
from providers.malwarebazaar import MalwareBazaarProvider
from providers.threatfox import ThreatFoxProvider
from providers.urlhaus import URLhausProvider
from providers.virustotal import VirusTotalProvider
from providers.http_utils import request_with_retry, is_transient_server_error
from utils import Verdict


def _response(status_code, headers=None):
    resp = MagicMock()
    resp.status_code = status_code
    resp.headers = headers or {}
    resp.ok = status_code < 400
    return resp


# --- Per-provider invalid-input rejection (no network call) ----------------

def test_virustotal_rejects_invalid_domain_without_request():
    vt = VirusTotalProvider(api_key="dummy")
    with patch("requests.get") as mock_get:
        result = vt.lookup_domain("wp-cron.php")
    mock_get.assert_not_called()
    assert result.verdict == Verdict.ERROR
    assert "Skipped" in result.details


def test_virustotal_rejects_invalid_ip_without_request():
    vt = VirusTotalProvider(api_key="dummy")
    with patch("requests.get") as mock_get:
        result = vt.lookup_ip("999.999.999.999")
    mock_get.assert_not_called()
    assert result.verdict == Verdict.ERROR


def test_virustotal_rejects_invalid_hash_without_request():
    vt = VirusTotalProvider(api_key="dummy")
    with patch("requests.get") as mock_get:
        result = vt.lookup_hash("not-a-hash")
    mock_get.assert_not_called()
    assert result.verdict == Verdict.ERROR


def test_abuseipdb_rejects_invalid_ip_without_request():
    provider = AbuseIPDBProvider(api_key="dummy")
    with patch("requests.get") as mock_get:
        result = provider.lookup_ip("not-an-ip")
    mock_get.assert_not_called()
    assert result.verdict == Verdict.ERROR


def test_urlhaus_rejects_malformed_url_without_request():
    provider = URLhausProvider(api_key=None)
    with patch("requests.post") as mock_post:
        result = provider.lookup_url("not a url")
    mock_post.assert_not_called()
    assert result.verdict == Verdict.ERROR


def test_malwarebazaar_rejects_invalid_hash_without_request():
    provider = MalwareBazaarProvider(api_key=None)
    with patch("requests.post") as mock_post:
        result = provider.lookup_hash("nothex")
    mock_post.assert_not_called()
    assert result.verdict == Verdict.ERROR


def test_threatfox_rejects_invalid_domain_without_request():
    provider = ThreatFoxProvider(api_key="dummy")
    with patch("requests.post") as mock_post:
        result = provider.lookup_domain("test.js")
    mock_post.assert_not_called()
    assert result.verdict == Verdict.ERROR


# --- No provider failure is ever classified CLEAN/MALICIOUS ----------------

def test_virustotal_400_never_classified_clean():
    vt = VirusTotalProvider(api_key="dummy")
    with patch("requests.get", return_value=_response(400)):
        result = vt.lookup_ip("8.8.8.8")
    assert result.verdict not in (Verdict.CLEAN, Verdict.MALICIOUS)


def test_virustotal_timeout_never_classified_clean():
    vt = VirusTotalProvider(api_key="dummy")
    with patch("requests.get", side_effect=requests.Timeout("timed out")):
        result = vt.lookup_ip("8.8.8.8")
    assert result.verdict not in (Verdict.CLEAN, Verdict.MALICIOUS)
    assert "Timeout" in result.details or "Unavailable" in result.details


def test_virustotal_connection_error_never_classified_clean():
    vt = VirusTotalProvider(api_key="dummy")
    with patch("requests.get", side_effect=requests.ConnectionError("refused")):
        result = vt.lookup_ip("8.8.8.8")
    assert result.verdict not in (Verdict.CLEAN, Verdict.MALICIOUS)


def test_otx_502_never_classified_clean():
    from providers.otx import OTXProvider
    otx = OTXProvider(api_key="dummy")
    with patch("requests.get", return_value=_response(502)):
        result = otx.lookup_domain("evil.example.com")
    assert result.verdict not in (Verdict.CLEAN, Verdict.MALICIOUS)


# --- Transient 5xx retry behavior -------------------------------------------

def test_is_transient_server_error_detects_502_503_504():
    for code in (502, 503, 504):
        assert is_transient_server_error(_response(code)) is True
    assert is_transient_server_error(_response(200)) is False
    assert is_transient_server_error(_response(400)) is False


def test_request_with_retry_retries_transient_server_error_then_succeeds():
    call_count = {"n": 0}

    def flaky():
        call_count["n"] += 1
        if call_count["n"] < 2:
            return _response(503)
        return _response(200)

    response = request_with_retry(flaky, "TestProvider")
    assert response.status_code == 200
    assert call_count["n"] == 2


def test_request_with_retry_does_not_retry_genuine_400():
    call_count = {"n": 0}

    def bad_request():
        call_count["n"] += 1
        return _response(400)

    response = request_with_retry(bad_request, "TestProvider")
    assert response.status_code == 400
    assert call_count["n"] == 1  # never retried
