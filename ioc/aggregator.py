"""
ioc/aggregator.py

Turns the raw, possibly-repeated IOC occurrences yielded by an extractor
into a deduplicated list of AggregatedIOC objects with accurate occurrence
counts.

Internal/external IPv4 classification is NOT performed here - it's
already been decided by the extractor at the moment each address was
found (see ip_classification.is_internal_ipv4, used by artifacts/_scan.py
and artifacts/pcap.py) and carried on RawIOC.is_internal. This module
just propagates that flag through deduplication so it survives into the
final AggregatedIOC, which the pipeline still needs for accurate
Internal/External summary counts even though internal addresses never
become lookup candidates.

Pipeline position:

    Extraction (incl. internal/external IPv4 classification) ->
    [Normalization -> Occurrence Counting -> Deduplication]  <- this
    module  -> Provider Capability Filtering -> Cache -> Lookup ->
    Classification -> Report
"""

from __future__ import annotations

from collections import OrderedDict
from typing import Iterable

from artifacts.base import RawIOC
from detector import IOCType
from ioc.models import AggregatedIOC
from ioc.normalizer import normalize_ioc


def aggregate_raw_iocs(raw_iocs: Iterable[RawIOC]) -> list[AggregatedIOC]:
    """
    Normalize, count, and deduplicate raw IOC occurrences.

    Returns one AggregatedIOC per distinct (normalized_value, ioc_type)
    pair, in first-seen order, with `occurrences` reflecting how many
    times that normalized IOC appeared in the artifact, and `is_internal`
    carried forward from extraction for IPv4 entries.
    """
    counts: "OrderedDict[tuple[str, IOCType], int]" = OrderedDict()
    internal_flags: dict[tuple[str, IOCType], bool] = {}

    for raw in raw_iocs:
        try:
            normalized = normalize_ioc(raw.value, raw.ioc_type)
        except (ValueError, TypeError):
            # A malformed value that slipped past extraction's own checks
            # (e.g. an edge-case IP the ipaddress module still rejects) is
            # simply skipped rather than crashing the whole analysis.
            continue

        if not normalized:
            continue

        key = (normalized, raw.ioc_type)
        counts[key] = counts.get(key, 0) + 1
        if raw.ioc_type == IOCType.IPV4:
            # Every occurrence of the same address classifies identically
            # (the flag depends only on the address itself), so it's safe
            # to just take whichever occurrence set it - no merge needed.
            internal_flags[key] = raw.is_internal

    aggregated: list[AggregatedIOC] = []
    for (value, ioc_type), occurrences in counts.items():
        aggregated.append(
            AggregatedIOC(
                value=value,
                ioc_type=ioc_type,
                occurrences=occurrences,
                is_internal=internal_flags.get((value, ioc_type), False),
            )
        )

    return aggregated
