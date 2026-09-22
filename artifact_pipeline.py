"""
artifact_pipeline.py

Orchestrates the full Artifact Analysis pipeline, wiring together the
artifact extractors, the ioc/ normalization+aggregation+classification
layers, the SQLite cache, and the existing provider manager:

    Extraction -> Normalization -> Occurrence Counting -> Deduplication
    -> Internal IPv4 Filtering -> Provider Capability Filtering -> Cache
    -> Threat Intelligence Lookup -> Result Normalization
    -> Classification -> Report

This module deliberately performs NO extraction or lookup logic itself -
it only sequences calls into artifacts/*, ioc/*, cache/*, and the
existing providers.manager / lookup modules, so each concern stays
testable and reusable in isolation.
"""

from __future__ import annotations

from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from artifacts.csv_extractor import CSVExtractor
from artifacts.detector import ArtifactType, detect_artifact_type
from artifacts.log import LogExtractor
from artifacts.pcap import PCAPExtractor
from artifacts.text import TextExtractor
from cache.cache import IOCCache
from config import AppConfig
from detector import IOCType
from ioc.aggregator import aggregate_raw_iocs
from ioc.classifier import CLASSIFICATION_PRIORITY, classify_by_hits, count_hits
from ioc.models import AggregatedIOC, IOCReportRow
from ioc.url_children import build_url_child_relationships, derive_url_host_children
from lookup import LOOKUP_METHOD, query_provider
from providers.http_utils import RateLimitTracker
from providers.manager import get_providers_for_type
from utils import ProviderResult, Verdict

_EXTRACTORS = {
    ArtifactType.TXT: TextExtractor(),
    ArtifactType.LOG: LogExtractor(),
    ArtifactType.CSV: CSVExtractor(),
    ArtifactType.PCAP: PCAPExtractor(),
    ArtifactType.PCAPNG: PCAPExtractor(),
}

_HASH_TYPES = (IOCType.MD5, IOCType.SHA1, IOCType.SHA256)

# Concurrency cap for the lookup phase - shared across every provider/IOC
# pair still pending after the cache pass, mirroring the bounded
# concurrency already used for single-IOC scans elsewhere in the project.
_MAX_LOOKUP_WORKERS = 16


class UnsupportedArtifactError(Exception):
    """Raised when the artifact's type cannot be determined/handled."""


class ArtifactReadError(Exception):
    """Raised when the artifact exists but cannot be parsed (corrupted, malformed, etc.)."""


def _ioc_key(value: str, ioc_type: IOCType) -> tuple[str, IOCType]:
    return (value, ioc_type)


def _tracked_lookup(
    provider,
    method_name: str,
    value: str,
    tracker: RateLimitTracker,
) -> tuple[ProviderResult, bool]:
    """
    Wraps query_provider with the per-run rate-limit circuit breaker
    (see providers.http_utils.RateLimitTracker): if this provider has
    already been confirmed rate-limited earlier in this run, skip the
    request entirely and return a synthetic RATE_LIMITED result instead
    of repeating a doomed call - this is what turns a bulk scan's
    "Provider: Rate limit exceeded (x33)" into a handful of genuine
    attempts followed by clean skips.

    Returns (result, was_real_request) - the caller uses the second
    value to decide whether to cache the result: a skip was never
    actually attempted against the API, so caching it would misrepresent
    a fetched result and could make a transient rate limit "sticky" for
    the cache's full TTL even after it clears.
    """
    if tracker.is_limited(provider.name):
        return (
            ProviderResult(
                provider=provider.name,
                verdict=Verdict.RATE_LIMITED,
                details="Rate limit exceeded earlier in this run - skipped to avoid further throttling",
            ),
            False,
        )

    result = query_provider(provider, method_name, value)
    if result.verdict == Verdict.RATE_LIMITED:
        tracker.mark_limited(provider.name)
    return result, True


def analyze_artifact(
    path: str,
    config: AppConfig,
    cache: IOCCache,
) -> tuple[list[IOCReportRow], dict]:
    """
    Run the full artifact analysis pipeline against the file at `path`.

    Returns (rows, summary):
        rows    - sorted list of IOCReportRow for the final report table
        summary - dict of counters for the pre-table summary panel

    Raises UnsupportedArtifactError or ArtifactReadError on failure; the
    caller (ioc_checker.py) is responsible for turning those into
    user-facing error panels, consistent with how -f/--file errors are
    already handled.
    """
    file_path = Path(path)
    if not file_path.is_file():
        raise ArtifactReadError(f"File not found: {path}")

    # Deliberately check emptiness by reading real bytes rather than
    # trusting file_path.stat().st_size. stat() can report a stale or
    # placeholder size (0) for files that are technically present but not
    # yet fully materialized locally - most commonly cloud-sync
    # placeholders (e.g. OneDrive Desktop/Documents backup on Windows,
    # which is exactly the kind of path - C:\Users\<user>\Desktop\... -
    # this bites). Actually opening and reading forces the OS to resolve
    # the real content instead of relying on metadata that may not have
    # caught up yet.
    try:
        with open(file_path, "rb") as handle:
            probe = handle.read(1)
    except OSError as exc:
        raise ArtifactReadError(f"Could not open file: {exc}") from exc
    if not probe:
        raise ArtifactReadError("File is empty")

    artifact_type = detect_artifact_type(path)
    if artifact_type == ArtifactType.UNKNOWN:
        hint = file_path.suffix.lstrip(".").upper() or "unknown"
        raise UnsupportedArtifactError(hint)

    extractor = _EXTRACTORS[artifact_type]
    try:
        raw_iocs = list(extractor.extract(path))
    except UnsupportedArtifactError:
        raise
    except Exception as exc:  # noqa: BLE001 - any extractor failure becomes a clean, reported error
        raise ArtifactReadError(str(exc)) from exc

    # `extracted_total` reflects only what the extractor itself found -
    # host children derived below are a pipeline enrichment, not a new
    # extraction result, so they deliberately don't inflate this count.
    extracted_total = len(raw_iocs)

    # For every extracted URL, derive its hostname as an additional,
    # independent child IOC occurrence (IPv4 or Domain - see
    # ioc/url_children.py). Feeding these through the same
    # aggregate_raw_iocs() call used for everything else means the child
    # gets the exact same deduplication and occurrence-counting treatment
    # as any other IOC, with no separate cache or lookup mechanism needed.
    derived_children = derive_url_host_children(raw_iocs)
    aggregated = aggregate_raw_iocs(raw_iocs + derived_children)

    # Parent URL -> child IOC relationships, recomputed from the final
    # deduplicated list so they can never disagree with what's actually
    # in `aggregated` (see build_url_child_relationships docstring).
    relationships = build_url_child_relationships(aggregated)

    return _lookup_and_report(path, aggregated, extracted_total, config, cache, relationships)


def _lookup_and_report(
    artifact_label: str,
    aggregated: list[AggregatedIOC],
    extracted_total: int,
    config: AppConfig,
    cache: IOCCache,
    relationships: dict[tuple[str, IOCType], list[str]] | None = None,
) -> tuple[list[IOCReportRow], dict]:
    relationships = relationships or {}
    type_counts = Counter(item.ioc_type for item in aggregated)

    internal_count = sum(1 for item in aggregated if item.is_internal)
    lookup_targets: list[tuple[AggregatedIOC, list]] = []

    for item in aggregated:
        if item.is_internal:
            continue  # never sent to external providers
        providers = get_providers_for_type(item.ioc_type, config)
        lookup_targets.append((item, providers))

    external_ipv4_count = sum(
        1 for item, _ in lookup_targets if item.ioc_type == IOCType.IPV4
    )

    # --- Cache pass: resolve whatever we can locally first -----------------
    pending: list[tuple[AggregatedIOC, object]] = []
    results_by_ioc: dict[tuple[str, IOCType], list] = {}
    cache_hits = 0

    for item, providers in lookup_targets:
        key = _ioc_key(item.value, item.ioc_type)
        results_by_ioc.setdefault(key, [])
        for provider in providers:
            cached = cache.get(item.value, item.ioc_type.value, provider.name)
            if cached is not None:
                results_by_ioc[key].append(cached)
                cache_hits += 1
            else:
                pending.append((item, provider))

    # --- Network pass: only IOC/provider pairs that missed the cache -------
    # A fresh RateLimitTracker is created per run (per analyze_artifact
    # call) - once a provider is confirmed rate-limited here, every
    # remaining pending lookup against it is skipped immediately rather
    # than repeating the same doomed request across potentially hundreds
    # of remaining IOCs, while every other provider keeps going normally.
    tracker = RateLimitTracker()
    lookups_performed = 0
    if pending:
        worker_count = min(_MAX_LOOKUP_WORKERS, len(pending))
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            futures = {
                executor.submit(
                    _tracked_lookup, provider, LOOKUP_METHOD[item.ioc_type], item.value, tracker
                ): (item, provider)
                for item, provider in pending
            }
            for future in as_completed(futures):
                item, provider = futures[future]
                result, was_real_request = future.result()
                if was_real_request:
                    lookups_performed += 1
                    # Only genuine responses are cached - a circuit-breaker
                    # skip never actually asked the API anything, so caching
                    # it would misrepresent a real result and could make a
                    # transient rate limit "sticky" past the point it clears.
                    cache.set(item.value, item.ioc_type.value, provider.name, result)
                results_by_ioc[_ioc_key(item.value, item.ioc_type)].append(result)

    # --- Build report rows --------------------------------------------------
    rows: list[IOCReportRow] = []
    for item, providers in lookup_targets:
        key = _ioc_key(item.value, item.ioc_type)
        results = results_by_ioc[key]
        hits = count_hits(results)
        classification = classify_by_hits(hits)
        # Primary parent for report rendering only - a child can have
        # multiple parent URLs (relationships[key] holds all of them),
        # but the table shows it once, nested under the first one seen
        # (see ui.print_artifact_table). This has no effect whatsoever on
        # this IOC's own reputation lookups, hits, or classification
        # above, which are computed completely independently.
        parents = relationships.get(key)
        parent_value = parents[0] if parents else None
        rows.append(
            IOCReportRow(
                ioc=item.value,
                ioc_type=item.ioc_type,
                occurrences=item.occurrences,
                classification=classification,
                hit_count=hits,
                applicable_count=len(providers),
                results=results,
                parent=parent_value,
            )
        )

    rows.sort(key=lambda r: (CLASSIFICATION_PRIORITY.get(r.classification, 4), -r.occurrences))

    summary = {
        "artifact": artifact_label,
        "extracted_total": extracted_total,
        "unique_total": len(aggregated),
        "ipv4_internal": internal_count,
        "ipv4_external": external_ipv4_count,
        "domains": type_counts.get(IOCType.DOMAIN, 0),
        "urls": type_counts.get(IOCType.URL, 0),
        "hashes": sum(type_counts.get(t, 0) for t in _HASH_TYPES),
        "lookups_performed": lookups_performed,
        "cache_hits": cache_hits,
    }

    return rows, summary
