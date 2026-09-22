"""
tests/test_ip_classification.py

Tests for ip_classification.is_internal_ipv4 - the single source of
truth for internal/external IPv4 classification, used at extraction time
by both text-based and PCAP extractors.
"""

from __future__ import annotations

from ip_classification import is_internal_ipv4


def test_rfc1918_private_ranges_are_internal():
    assert is_internal_ipv4("10.0.0.1") is True
    assert is_internal_ipv4("172.16.0.1") is True
    assert is_internal_ipv4("192.168.1.1") is True


def test_loopback_is_internal():
    assert is_internal_ipv4("127.0.0.1") is True


def test_link_local_is_internal():
    assert is_internal_ipv4("169.254.1.1") is True


def test_multicast_is_internal():
    """
    Multicast must be treated as internal/non-lookup-worthy even though
    ipaddress.IPv4Address.is_global reports multicast addresses as
    "global" - is_internal_ipv4 deliberately does not rely on is_global
    alone for exactly this reason.
    """
    assert is_internal_ipv4("224.0.0.1") is True


def test_reserved_is_internal():
    assert is_internal_ipv4("240.0.0.1") is True


def test_unspecified_is_internal():
    assert is_internal_ipv4("0.0.0.0") is True


def test_ordinary_public_addresses_are_external():
    assert is_internal_ipv4("8.8.8.8") is False
    assert is_internal_ipv4("185.10.20.30") is False
    assert is_internal_ipv4("1.1.1.1") is False


def test_invalid_value_is_not_internal():
    assert is_internal_ipv4("not-an-ip") is False
