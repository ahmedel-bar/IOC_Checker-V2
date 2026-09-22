"""
tests/test_classification_consistency.py

The core regression from this round: detector.py (direct CLI) and
artifacts/_scan.py (artifact extraction) must classify every value
identically, because both now delegate to the single canonical
domain_validation.is_valid_domain(). Also covers the regex-backtracking
bug this exposed ("th.bing.c" silently matching as truncated "th.bing").
"""

from __future__ import annotations

from artifacts._scan import scan_text_for_iocs
from detector import IOCType, detect_ioc_type

_MUST_NOT_BE_DOMAIN = [
    "c",
    "xpaywa",
    "th.bing.c",
    "wp-cron.php",
    "index.php",
    "index.html",
    "test.js",
]

_MUST_BE_DOMAIN = [
    "evil.example.com",
    "proxyjudge1.proxyfire.net",
    "www.wantsfly.com",
    "help.naver.com",
]


def test_direct_cli_rejects_invalid_values():
    for value in _MUST_NOT_BE_DOMAIN:
        assert detect_ioc_type(value) == IOCType.UNKNOWN, value


def test_direct_cli_accepts_real_domains():
    for value in _MUST_BE_DOMAIN:
        assert detect_ioc_type(value) == IOCType.DOMAIN, value


def test_artifact_extraction_rejects_invalid_values():
    for value in _MUST_NOT_BE_DOMAIN:
        text = f"token: {value}\n"
        domains = [i.value for i in scan_text_for_iocs(text) if i.ioc_type == IOCType.DOMAIN]
        assert value not in domains, value


def test_artifact_extraction_accepts_real_domains():
    for value in _MUST_BE_DOMAIN:
        text = f"token: {value}\n"
        domains = [i.value for i in scan_text_for_iocs(text) if i.ioc_type == IOCType.DOMAIN]
        assert value in domains, value


def test_direct_cli_and_artifact_extraction_agree_on_every_case():
    """
    The actual regression: for every test value, the direct CLI's
    classification and the artifact path's classification must produce
    the same accept/reject decision.
    """
    for value in _MUST_NOT_BE_DOMAIN + _MUST_BE_DOMAIN:
        direct_says_domain = detect_ioc_type(value) == IOCType.DOMAIN
        text = f"token: {value}\n"
        artifact_domains = [i.value for i in scan_text_for_iocs(text) if i.ioc_type == IOCType.DOMAIN]
        artifact_says_domain = value in artifact_domains
        assert direct_says_domain == artifact_says_domain, (
            f"{value}: direct={direct_says_domain} artifact={artifact_says_domain}"
        )


def test_regex_does_not_truncate_invalid_multi_label_value():
    """
    The specific bug found while investigating this issue: a naive
    domain-matching regex can backtrack and silently match a truncated
    PREFIX of a longer invalid token ("th.bing.c" -> "th.bing") instead
    of correctly rejecting the whole thing, because ".bing" happens to be
    a real, currently-delegated gTLD. The whole token must be evaluated
    as one unit, with no fallback to a shorter internal match.
    """
    text = "referrer: th.bing.c\n"
    domains = [i.value for i in scan_text_for_iocs(text) if i.ioc_type == IOCType.DOMAIN]
    assert "th.bing.c" not in domains
    assert "th.bing" not in domains


def test_standalone_real_domain_under_bing_tld_still_works():
    """
    The flip side of the above: a real domain under the real .bing gTLD,
    appearing on its own (not as a truncated remnant of something
    longer), is legitimately valid and must still be extracted.
    """
    text = "referrer: th.bing\n"
    domains = [i.value for i in scan_text_for_iocs(text) if i.ioc_type == IOCType.DOMAIN]
    assert "th.bing" in domains
