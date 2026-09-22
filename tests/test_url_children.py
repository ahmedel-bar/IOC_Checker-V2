"""
tests/test_url_children.py

Tests for ioc/url_children.py: deriving an IPv4/Domain child IOC from a
URL's hostname, and the parent -> child relationship map used by the
artifact report table.
"""

from __future__ import annotations

from artifacts.base import RawIOC
from detector import IOCType
from ioc.aggregator import aggregate_raw_iocs
from ioc.url_children import (
    build_url_child_relationships,
    derive_url_host_children,
    extract_host_ioc,
)


# --- extract_host_ioc --------------------------------------------------

def test_extracts_ipv4_host_from_url():
    child = extract_host_ioc("http://87.96.21.84/Invoke-SMBExec.ps1")
    assert child is not None
    assert child.value == "87.96.21.84"
    assert child.ioc_type == IOCType.IPV4


def test_extracts_domain_host_from_url():
    child = extract_host_ioc("http://example.com/malware.exe")
    assert child is not None
    assert child.value == "example.com"
    assert child.ioc_type == IOCType.DOMAIN


def test_valid_url_that_threatfox_would_reject_still_yields_domain_child():
    url = (
        "http://ctldl.windowsupdate.com/msdownload/update/v3/static/"
        "trustedr/en/pinrulestl.cab?d3434c35564aa4e5"
    )
    child = extract_host_ioc(url)
    assert child is not None
    assert child.value == "ctldl.windowsupdate.com"
    assert child.ioc_type == IOCType.DOMAIN


def test_malformed_url_yields_no_child():
    assert extract_host_ioc("not a url at all") is None


def test_url_with_no_host_yields_no_child():
    assert extract_host_ioc("http:///just/a/path") is None


def test_ipv6_host_yields_no_child():
    # Out of scope for this feature - only IPv4 and Domain children.
    assert extract_host_ioc("http://[::1]/x") is None


def test_filename_shaped_host_yields_no_child():
    assert extract_host_ioc("http://wp-cron.php/x") is None


def test_internal_ip_host_is_flagged_internal():
    child = extract_host_ioc("http://10.0.0.5/beacon")
    assert child is not None
    assert child.ioc_type == IOCType.IPV4
    assert child.is_internal is True


# --- derive_url_host_children -------------------------------------------

def test_derive_children_ignores_non_url_entries():
    raw = [
        RawIOC("evil.com", IOCType.DOMAIN),
        RawIOC("8.8.8.8", IOCType.IPV4),
    ]
    assert derive_url_host_children(raw) == []


def test_derive_children_one_per_url_occurrence():
    raw = [
        RawIOC("http://87.96.21.84/a.exe", IOCType.URL),
        RawIOC("http://87.96.21.84/b.exe", IOCType.URL),
        RawIOC("http://87.96.21.84/c.exe", IOCType.URL),
    ]
    derived = derive_url_host_children(raw)
    assert len(derived) == 3
    assert all(d.value == "87.96.21.84" and d.ioc_type == IOCType.IPV4 for d in derived)


def test_derive_children_then_aggregate_dedupes_to_one_child():
    """
    The whole point: feeding derived children through the existing
    aggregate_raw_iocs() collapses repeated occurrences of the same host
    into a single AggregatedIOC, exactly like any other IOC.
    """
    raw = [
        RawIOC("http://87.96.21.84/a.exe", IOCType.URL),
        RawIOC("http://87.96.21.84/b.exe", IOCType.URL),
        RawIOC("http://87.96.21.84/c.exe", IOCType.URL),
    ]
    derived = derive_url_host_children(raw)
    aggregated = aggregate_raw_iocs(raw + derived)

    ip_entries = [a for a in aggregated if a.ioc_type == IOCType.IPV4]
    url_entries = [a for a in aggregated if a.ioc_type == IOCType.URL]

    assert len(ip_entries) == 1
    assert ip_entries[0].value == "87.96.21.84"
    assert ip_entries[0].occurrences == 3
    assert len(url_entries) == 3  # each URL is still its own distinct IOC


def test_child_merges_with_independently_extracted_domain():
    """
    If the same domain also appears standalone elsewhere in the artifact,
    it must reuse that single IOC rather than creating a duplicate.
    """
    raw = [
        RawIOC("http://example.com/malware.exe", IOCType.URL),
        RawIOC("example.com", IOCType.DOMAIN),  # also seen standalone
    ]
    derived = derive_url_host_children(raw)
    aggregated = aggregate_raw_iocs(raw + derived)

    domain_entries = [a for a in aggregated if a.ioc_type == IOCType.DOMAIN]
    assert len(domain_entries) == 1
    assert domain_entries[0].value == "example.com"
    assert domain_entries[0].occurrences == 2


# --- build_url_child_relationships ---------------------------------------

def test_relationship_maps_child_back_to_single_parent():
    raw = [RawIOC("http://example.com/malware.exe", IOCType.URL)]
    derived = derive_url_host_children(raw)
    aggregated = aggregate_raw_iocs(raw + derived)

    relationships = build_url_child_relationships(aggregated)
    key = ("example.com", IOCType.DOMAIN)
    assert relationships[key] == ["http://example.com/malware.exe"]


def test_relationship_maps_child_to_multiple_parents_in_first_seen_order():
    raw = [
        RawIOC("http://87.96.21.84/a.exe", IOCType.URL),
        RawIOC("http://87.96.21.84/b.exe", IOCType.URL),
        RawIOC("http://87.96.21.84/c.exe", IOCType.URL),
    ]
    derived = derive_url_host_children(raw)
    aggregated = aggregate_raw_iocs(raw + derived)

    relationships = build_url_child_relationships(aggregated)
    key = ("87.96.21.84", IOCType.IPV4)
    assert relationships[key] == [
        "http://87.96.21.84/a.exe",
        "http://87.96.21.84/b.exe",
        "http://87.96.21.84/c.exe",
    ]


def test_url_with_no_valid_child_has_no_relationship_entry():
    raw = [RawIOC("http://[::1]/x", IOCType.URL)]
    derived = derive_url_host_children(raw)
    aggregated = aggregate_raw_iocs(raw + derived)

    relationships = build_url_child_relationships(aggregated)
    assert relationships == {}
