"""
ioc/url_children.py

Derives a child IPv4/Domain IOC from each extracted URL's hostname.

The URL itself always remains the PARENT IOC (unchanged - extraction in
artifacts/*.py still emits only the URL for every URL match, exactly as
before, see artifacts/_scan.py's module docstring). This module adds one
extra, independent pipeline step that runs strictly AFTER extraction and
BEFORE aggregation:

    Extraction -> [derive_url_host_children] -> Normalization ->
    Occurrence Counting -> Deduplication (ioc/aggregator.py) -> ...

For every URL occurrence, its hostname is parsed and classified as either
a valid IPv4 address or a valid domain, and emitted as an additional
RawIOC "occurrence" of that host. Feeding these synthetic occurrences
through the existing aggregate_raw_iocs() call - the same call already
used for every other IOC - means:

    - Global deduplication is free: three URLs sharing the same host
      collapse into a single child AggregatedIOC via the same
      (normalized_value, ioc_type) key every other IOC uses, so the child
      only receives ONE provider lookup regardless of how many parent
      URLs reference it.
    - A host that also appears independently elsewhere in the artifact
      (e.g. as a bare domain outside any URL) merges into that same
      single AggregatedIOC rather than becoming a duplicate, per the
      "reuse it rather than creating a duplicate IOC" requirement.
    - Occurrence counting for the child falls out of the exact same
      counting logic used for every other IOC, instead of a bespoke rule
      that would need to be kept in sync with it separately.

Parent -> child relationships (needed only for report rendering, e.g.
"which URL row does this child render under") are computed separately
by build_url_child_relationships(), from the final deduplicated URL
list, so they always agree with what actually ended up in the
aggregated set.
"""

from __future__ import annotations

import ipaddress
from typing import Iterable
from urllib.parse import urlsplit

from artifacts.base import RawIOC
from detector import IOCType
from domain_validation import is_valid_domain
from ioc.models import AggregatedIOC
from ioc.normalizer import normalize_ioc
from ip_classification import is_internal_ipv4


def extract_host_ioc(url: str) -> RawIOC | None:
    """
    Parse `url`'s hostname and classify it as an IPv4 or Domain child IOC.

    Returns None - i.e. "no child IOC" - for:
        - a malformed URL that can't be parsed at all
        - a URL with no hostname component
        - a hostname that is neither a valid IPv4 address nor a valid
          domain (e.g. an IPv6 host, which this feature deliberately
          doesn't cover - see the parent spec's EXTRACTION RULE, which
          only names IPv4 and Domain as child types)

    Only ever called with a URL's own value - never a standalone
    candidate - so domain_validation.is_valid_domain's "never call this
    on part of a URL" warning does not apply here: this function passes
    it the parsed *hostname* only, never the URL's path (which is
    exactly the part that warning is about).
    """
    try:
        parts = urlsplit(url.strip())
    except ValueError:
        return None

    # SplitResult.hostname is already lowercased with any userinfo, port,
    # and IPv6 brackets stripped - normalization for the IOC-type-specific
    # canonical form still happens later, in ioc/normalizer.py, same as
    # for every other IOC.
    host = parts.hostname
    if not host:
        return None

    try:
        ipaddress.IPv4Address(host)
    except ValueError:
        pass
    else:
        return RawIOC(value=host, ioc_type=IOCType.IPV4, is_internal=is_internal_ipv4(host))

    if is_valid_domain(host):
        return RawIOC(value=host, ioc_type=IOCType.DOMAIN)

    return None


def derive_url_host_children(raw_iocs: Iterable[RawIOC]) -> list[RawIOC]:
    """
    Return one derived host RawIOC per URL occurrence in `raw_iocs`
    (skipping URLs whose host doesn't yield a valid child - see
    extract_host_ioc). The caller is expected to append these to the
    original raw_iocs list before handing everything to
    ioc.aggregator.aggregate_raw_iocs, so children get the exact same
    occurrence-counting and deduplication treatment as every other IOC.

    This never touches or reorders the original list, and never emits
    anything for non-URL entries - existing extraction/occurrence
    behavior for every other IOC type is completely unaffected.
    """
    derived: list[RawIOC] = []
    for raw in raw_iocs:
        if raw.ioc_type != IOCType.URL:
            continue
        child = extract_host_ioc(raw.value)
        if child is not None:
            derived.append(child)
    return derived


def build_url_child_relationships(
    aggregated: list[AggregatedIOC],
) -> dict[tuple[str, IOCType], list[str]]:
    """
    Map each child IOC's (normalized_value, ioc_type) key to the list of
    parent URL values (already-normalized, first-seen order, no
    duplicates) that reference it, based on the final deduplicated
    `aggregated` list.

    Recomputing this from the deduplicated URLs (rather than carrying it
    through from derive_url_host_children) guarantees it can never
    disagree with what's actually in `aggregated` - e.g. a child that
    was filtered out (an internal IPv4 host) simply won't have a usable
    entry, without this module needing to know anything about that
    filtering.
    """
    aggregated_keys = {(item.value, item.ioc_type) for item in aggregated}
    relationships: dict[tuple[str, IOCType], list[str]] = {}

    for item in aggregated:
        if item.ioc_type != IOCType.URL:
            continue
        child = extract_host_ioc(item.value)
        if child is None:
            continue
        try:
            normalized_value = normalize_ioc(child.value, child.ioc_type)
        except (ValueError, TypeError):
            continue
        key = (normalized_value, child.ioc_type)
        if key not in aggregated_keys:
            continue
        parents = relationships.setdefault(key, [])
        if item.value not in parents:
            parents.append(item.value)

    return relationships
