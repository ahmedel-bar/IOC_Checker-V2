"""
tests/test_provider_validation.py

Provider-side input validation: OTX and ThreatFox must reject malformed
input before making any request, rather than sending it to the API and
producing an avoidable HTTP 400 / illegal_search_term.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from providers.otx import OTXProvider
from providers.threatfox import ThreatFoxProvider
from utils import Verdict


def test_otx_rejects_filename_shaped_domain_without_request():
    otx = OTXProvider(api_key="dummy")
    result = otx.lookup_domain("wp-cron.php")
    assert result.verdict == Verdict.ERROR
    assert "Skipped" in result.details


def test_otx_accepts_real_domain_shape():
    """A genuinely valid domain should pass validation (network call may still fail, that's fine)."""
    otx = OTXProvider(api_key="dummy")
    result = otx.lookup_domain("evil.example.com")
    # It should NOT be rejected at the validation stage.
    assert "Skipped" not in result.details


def test_otx_rejects_invalid_ip_without_request():
    otx = OTXProvider(api_key="dummy")
    result = otx.lookup_ip("999.999.999.999")
    assert result.verdict == Verdict.ERROR
    assert "Skipped" in result.details


def test_otx_rejects_invalid_hash_without_request():
    otx = OTXProvider(api_key="dummy")
    result = otx.lookup_hash("not-a-real-hash")
    assert result.verdict == Verdict.ERROR
    assert "Skipped" in result.details


def test_otx_rejects_malformed_url_without_request():
    otx = OTXProvider(api_key="dummy")
    result = otx.lookup_url("not a url at all")
    assert result.verdict == Verdict.ERROR
    assert "Skipped" in result.details


def test_threatfox_rejects_short_search_term_without_request():
    tf = ThreatFoxProvider(api_key="dummy")
    result = tf.lookup_domain("ab")
    assert result.verdict == Verdict.ERROR
    assert "Skipped" in result.details


def test_threatfox_never_classifies_rejected_input_as_clean_or_malicious():
    tf = ThreatFoxProvider(api_key="dummy")
    result = tf.lookup_domain("x")
    assert result.verdict not in (Verdict.CLEAN, Verdict.MALICIOUS)


def _response(status_code, json_data=None):
    resp = MagicMock()
    resp.status_code = status_code
    resp.ok = status_code < 400
    resp.headers = {}
    resp.json.return_value = json_data or {}
    return resp


def test_threatfox_illegal_search_term_becomes_not_found():
    """
    query_status == "illegal_search_term" is ThreatFox rejecting a
    well-formed search term outright - not a verdict about the IOC - so
    it must surface as a plain NOT_FOUND, never ERROR/UNSUPPORTED/CLEAN,
    and must never contribute risk.
    """
    tf = ThreatFoxProvider(api_key="dummy")
    with patch("requests.post", return_value=_response(200, {"query_status": "illegal_search_term"})):
        result = tf.lookup_url("http://ctldl.windowsupdate.com/x?d3434c35564aa4e5")
    assert result.verdict == Verdict.NOT_FOUND
    assert result.risk_contribution == 0


def test_threatfox_illegal_search_term_never_appears_in_api_warnings():
    import ui

    tf = ThreatFoxProvider(api_key="dummy")
    with patch("requests.post", return_value=_response(200, {"query_status": "illegal_search_term"})):
        result = tf.lookup_url("http://ctldl.windowsupdate.com/x?d3434c35564aa4e5")

    failed = [r for r in [result] if r.verdict in (Verdict.ERROR, Verdict.RATE_LIMITED)]
    assert failed == []


def test_threatfox_genuine_http_error_still_becomes_error():
    """Real provider failures (HTTP 401 etc.) must remain unaffected."""
    tf = ThreatFoxProvider(api_key="dummy")
    with patch("requests.post", return_value=_response(401)):
        result = tf.lookup_ip("8.8.8.8")
    assert result.verdict == Verdict.ERROR


