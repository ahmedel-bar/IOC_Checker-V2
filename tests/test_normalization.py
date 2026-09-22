"""
tests/test_normalization.py

Normalization tests: case folding, trailing dots, hash lowercasing, IPv4
canonicalization, and URL scheme/host normalization.
"""

from __future__ import annotations

from detector import IOCType
from ioc.normalizer import normalize_ioc


def test_domain_case_and_trailing_dot_collapse_to_one_value():
    variants = ["evil.com", "EVIL.COM", "evil.com."]
    normalized = {normalize_ioc(v, IOCType.DOMAIN) for v in variants}
    assert normalized == {"evil.com"}


def test_hash_normalized_to_lowercase():
    assert (
        normalize_ioc("44D88612FEA8A8F36DE82E1278ABB02F", IOCType.MD5)
        == "44d88612fea8a8f36de82e1278abb02f"
    )


def test_ipv4_leading_zeros_normalized():
    assert normalize_ioc("010.010.000.001", IOCType.IPV4) == "10.10.0.1"


def test_ipv4_already_canonical_unchanged():
    assert normalize_ioc("185.10.20.30", IOCType.IPV4) == "185.10.20.30"


def test_url_scheme_and_host_lowercased_path_preserved():
    result = normalize_ioc("HTTP://EVIL.COM/Path?X=1", IOCType.URL)
    assert result == "http://evil.com/Path?X=1"
