"""
tests/test_aggregation.py

Deduplication + occurrence counting, and internal-vs-external IPv4
classification, both via ioc/aggregator.py.
"""

from __future__ import annotations

from artifacts.base import RawIOC
from detector import IOCType
from ioc.aggregator import aggregate_raw_iocs


def test_repeated_ioc_deduplicates_with_correct_occurrence_count():
    raw = [RawIOC("185.10.20.30", IOCType.IPV4) for _ in range(100)]
    aggregated = aggregate_raw_iocs(raw)

    assert len(aggregated) == 1
    assert aggregated[0].value == "185.10.20.30"
    assert aggregated[0].occurrences == 100


def test_case_variants_of_same_domain_merge_into_one_entry():
    raw = (
        [RawIOC("evil.com", IOCType.DOMAIN)] * 5
        + [RawIOC("EVIL.COM", IOCType.DOMAIN)] * 3
        + [RawIOC("evil.com.", IOCType.DOMAIN)] * 2
    )
    aggregated = aggregate_raw_iocs(raw)

    assert len(aggregated) == 1
    assert aggregated[0].value == "evil.com"
    assert aggregated[0].occurrences == 10


def test_different_ioc_types_are_not_merged_even_with_same_text():
    # Extremely unlikely in practice, but the (value, type) key must be
    # what defines uniqueness, not value alone.
    raw = [RawIOC("abc", IOCType.DOMAIN), RawIOC("abc", IOCType.URL)]
    aggregated = aggregate_raw_iocs(raw)
    assert len(aggregated) == 2


def test_internal_flag_propagated_from_extraction(tmp_path=None):
    """
    Internal/external classification now happens at extraction time (see
    ip_classification.is_internal_ipv4, used by the extractors) - the
    aggregator's job is just to propagate whatever RawIOC.is_internal
    already says, not to (re)classify. This mirrors what a real
    extractor would produce.
    """
    raw = [
        RawIOC("10.0.0.1", IOCType.IPV4, is_internal=True),
        RawIOC("172.16.0.1", IOCType.IPV4, is_internal=True),
        RawIOC("192.168.1.1", IOCType.IPV4, is_internal=True),
        RawIOC("127.0.0.1", IOCType.IPV4, is_internal=True),
        RawIOC("169.254.1.1", IOCType.IPV4, is_internal=True),
    ]
    aggregated = aggregate_raw_iocs(raw)

    assert all(item.is_internal for item in aggregated)


def test_external_flag_propagated_from_extraction():
    raw = [
        RawIOC("185.10.20.30", IOCType.IPV4, is_internal=False),
        RawIOC("8.8.8.8", IOCType.IPV4, is_internal=False),
    ]
    aggregated = aggregate_raw_iocs(raw)

    assert all(not item.is_internal for item in aggregated)


def test_repeated_occurrences_of_internal_ip_keep_flag_and_correct_count():
    """The is_internal flag must survive deduplication alongside the count."""
    raw = [RawIOC("10.0.0.5", IOCType.IPV4, is_internal=True) for _ in range(12)]
    aggregated = aggregate_raw_iocs(raw)

    assert len(aggregated) == 1
    assert aggregated[0].is_internal is True
    assert aggregated[0].occurrences == 12


def test_non_ipv4_types_never_flagged_internal():
    raw = [RawIOC("evil.com", IOCType.DOMAIN), RawIOC("aa" * 16, IOCType.MD5)]
    aggregated = aggregate_raw_iocs(raw)
    assert all(not item.is_internal for item in aggregated)
