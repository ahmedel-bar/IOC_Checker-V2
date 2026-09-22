"""
tests/test_urlhaus_host_api.py

URLhaus now supports Domain and IPv4 lookups via the Host API
(POST /v1/host/), in addition to the existing URL lookup
(POST /v1/url/). Covers correct endpoint routing, response parsing
against the real API schema, input validation, and that hashes remain
unsupported with no fake-URL construction anywhere.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import requests

from detector import IOCType
from providers.urlhaus import HOST_API, URL_API, URLhausProvider
from utils import Verdict


def _response(status_code=200, json_data=None, headers=None):
    r = MagicMock()
    r.status_code = status_code
    r.ok = status_code < 400
    r.headers = headers or {}
    if json_data is not None:
        r.json.return_value = json_data
    return r


# --- Capability declaration ------------------------------------------

def test_supported_types_includes_url_domain_ipv4_not_hash():
    provider = URLhausProvider(api_key=None)
    assert provider.SUPPORTED_TYPES == {IOCType.URL, IOCType.DOMAIN, IOCType.IPV4}


def test_lookup_hash_is_unsupported_and_makes_no_request():
    provider = URLhausProvider(api_key=None)
    with patch("requests.post") as mock_post:
        result = provider.lookup_hash("d" * 64)
    mock_post.assert_not_called()
    assert result.verdict == Verdict.UNSUPPORTED


# --- Endpoint routing --------------------------------------------------

def test_lookup_url_uses_url_endpoint():
    provider = URLhausProvider(api_key=None)
    with patch("requests.post", return_value=_response(json_data={"query_status": "no_results"})) as mock_post:
        provider.lookup_url("http://evil.example.com/payload.exe")
    called_url = mock_post.call_args[0][0]
    called_data = mock_post.call_args[1]["data"]
    assert called_url == URL_API
    assert called_data == {"url": "http://evil.example.com/payload.exe"}


def test_lookup_domain_uses_host_endpoint():
    provider = URLhausProvider(api_key=None)
    with patch("requests.post", return_value=_response(json_data={"query_status": "no_results"})) as mock_post:
        provider.lookup_domain("evil.example.com")
    called_url = mock_post.call_args[0][0]
    called_data = mock_post.call_args[1]["data"]
    assert called_url == HOST_API
    assert called_data == {"host": "evil.example.com"}


def test_lookup_ip_uses_host_endpoint():
    provider = URLhausProvider(api_key=None)
    with patch("requests.post", return_value=_response(json_data={"query_status": "no_results"})) as mock_post:
        provider.lookup_ip("185.10.20.30")
    called_url = mock_post.call_args[0][0]
    called_data = mock_post.call_args[1]["data"]
    assert called_url == HOST_API
    assert called_data == {"host": "185.10.20.30"}


def test_no_fake_url_constructed_for_domain_or_ip_lookup():
    """Domains and IPs must be sent as-is to the host endpoint, never wrapped as a fake URL."""
    provider = URLhausProvider(api_key=None)
    with patch("requests.post", return_value=_response(json_data={"query_status": "no_results"})) as mock_post:
        provider.lookup_domain("evil.example.com")
        provider.lookup_ip("185.10.20.30")
    for call in mock_post.call_args_list:
        data = call[1]["data"]
        for value in data.values():
            assert "http://" not in value and "https://" not in value


# --- Response parsing against the real Host API schema ------------------

def test_host_lookup_malicious_when_online_url_present():
    provider = URLhausProvider(api_key=None)
    payload = {
        "query_status": "ok",
        "firstseen": "2019-01-19 01:33:26 UTC",
        "url_count": "3",
        "blacklists": {"spamhaus_dbl": "abused_legit_malware", "surbl": "listed"},
        "urlhaus_reference": "https://urlhaus.abuse.ch/host/evil.example.com/",
        "urls": [
            {"url": "http://evil.example.com/a", "url_status": "online"},
            {"url": "http://evil.example.com/b", "url_status": "offline"},
        ],
    }
    with patch("requests.post", return_value=_response(json_data=payload)):
        result = provider.lookup_domain("evil.example.com")
    assert result.verdict == Verdict.MALICIOUS
    assert result.risk_contribution == 30


def test_host_lookup_suspicious_when_only_offline_urls():
    provider = URLhausProvider(api_key=None)
    payload = {
        "query_status": "ok",
        "firstseen": "2020-01-01",
        "url_count": "2",
        "blacklists": {},
        "urls": [
            {"url": "http://old.example.com/a", "url_status": "offline"},
            {"url": "http://old.example.com/b", "url_status": "offline"},
        ],
    }
    with patch("requests.post", return_value=_response(json_data=payload)):
        result = provider.lookup_ip("185.10.20.30")
    assert result.verdict == Verdict.SUSPICIOUS


def test_host_lookup_clean_when_no_urls():
    provider = URLhausProvider(api_key=None)
    payload = {"query_status": "ok", "url_count": "0", "urls": [], "blacklists": {}}
    with patch("requests.post", return_value=_response(json_data=payload)):
        result = provider.lookup_ip("1.1.1.1")
    assert result.verdict == Verdict.CLEAN


def test_host_lookup_not_found():
    provider = URLhausProvider(api_key=None)
    with patch("requests.post", return_value=_response(json_data={"query_status": "no_results"})):
        result = provider.lookup_domain("clean.example.com")
    assert result.verdict == Verdict.NOT_FOUND


def test_host_lookup_error_status_never_clean_or_malicious():
    provider = URLhausProvider(api_key=None)
    with patch("requests.post", return_value=_response(json_data={"query_status": "invalid_host"})):
        result = provider.lookup_domain("evil.example.com")
    assert result.verdict not in (Verdict.CLEAN, Verdict.MALICIOUS)


# --- Input validation (defense-in-depth, no request for invalid input) --

def test_lookup_domain_rejects_invalid_domain_without_request():
    provider = URLhausProvider(api_key=None)
    with patch("requests.post") as mock_post:
        result = provider.lookup_domain("wp-cron.php")
    mock_post.assert_not_called()
    assert result.verdict == Verdict.ERROR


def test_lookup_ip_rejects_invalid_ip_without_request():
    provider = URLhausProvider(api_key=None)
    with patch("requests.post") as mock_post:
        result = provider.lookup_ip("not-an-ip")
    mock_post.assert_not_called()
    assert result.verdict == Verdict.ERROR


# --- Existing behavior preserved -----------------------------------------

def test_url_lookup_behavior_unchanged():
    provider = URLhausProvider(api_key=None)
    payload = {"query_status": "ok", "url_status": "online", "threat": "malware_download", "tags": ["exe"]}
    with patch("requests.post", return_value=_response(json_data=payload)):
        result = provider.lookup_url("http://evil.example.com/malware.exe")
    assert result.verdict == Verdict.MALICIOUS
    assert result.risk_contribution == 30
    assert "URL Status: online" in result.details


def test_rate_limit_handling_preserved_for_host_lookup():
    provider = URLhausProvider(api_key="dummy")
    with patch("requests.post", return_value=_response(status_code=429, headers={"Retry-After": "0.01"})):
        result = provider.lookup_domain("evil.example.com")
    assert result.verdict == Verdict.RATE_LIMITED


def test_timeout_handling_preserved_for_host_lookup():
    provider = URLhausProvider(api_key=None)
    with patch("requests.post", side_effect=requests.Timeout("timed out")):
        result = provider.lookup_ip("8.8.8.8")
    assert result.verdict == Verdict.ERROR
    assert "Timeout" in result.details


def test_auth_key_header_still_supported():
    provider = URLhausProvider(api_key="my-auth-key")
    with patch("requests.post", return_value=_response(json_data={"query_status": "no_results"})) as mock_post:
        provider.lookup_domain("evil.example.com")
    headers = mock_post.call_args[1]["headers"]
    assert headers.get("Auth-Key") == "my-auth-key"
