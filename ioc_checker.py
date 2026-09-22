#!/usr/bin/env python3
"""
ioc_checker.py

Threat Intelligence Aggregator CLI
-----------------------------------
Look up a single IOC (IPv4, Domain, URL, or hash) against VirusTotal,
AlienVault OTX, and ThreatFox concurrently, then present a unified
risk assessment.

Usage:
    python ioc_checker.py <IOC>
    python ioc_checker.py -f/--file <path>
    python ioc_checker.py -a/--artifact <path>

Examples:
    python ioc_checker.py 8.8.8.8
    python ioc_checker.py google.com
    python ioc_checker.py https://evil.com/login
    python ioc_checker.py 44d88612fea8a8f36de82e1278abb02f
    python ioc_checker.py -f malware.exe
    python ioc_checker.py -a capture.pcap
    python ioc_checker.py -a network.log
    python ioc_checker.py -a indicators.csv

When a file is supplied via -f/--file, its MD5/SHA1/SHA256 are calculated
locally and displayed, then only the SHA256 is run through the normal
hash lookup workflow (identical to passing that SHA256 on the command
line) - this is unchanged from before.

-a/--artifact is a different, additional feature: it extracts every IOC
(IPv4, Domain, URL, MD5, SHA1, SHA256) found inside the supplied artifact
(TXT/LOG/CSV/PCAP/PCAPNG), deduplicates them, filters out internal IPv4
addresses, looks up only the external ones, and produces a single sorted
IOC report - see artifact_pipeline.py for the full pipeline.
"""

from __future__ import annotations

import argparse
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from rich.console import Console

import ui
from artifact_pipeline import ArtifactReadError, UnsupportedArtifactError, analyze_artifact
from cache.cache import IOCCache
from config import CACHE_DB_PATH, CACHE_TTL_SECONDS, load_config
from detector import IOCType, detect_ioc_type
from lookup import LOOKUP_METHOD as _LOOKUP_METHOD
from lookup import query_provider
from providers import BaseProvider
from providers.manager import get_providers_for_type
from utils import ProviderResult, Verdict, calculate_file_hashes, setup_logging

console = Console()
logger = setup_logging()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="ioc_checker.py",
        description="Threat Intelligence Aggregator CLI - lookup an IOC across "
        "VirusTotal, AlienVault OTX, and ThreatFox.",
    )
    # The positional IOC is optional so that -f/--file or -a/--artifact can
    # be used instead. Exactly one of (ioc, --file, --artifact) must be
    # supplied; this is validated below.
    parser.add_argument(
        "ioc",
        nargs="?",
        default=None,
        help="The indicator of compromise to look up (IP, domain, URL, or hash)",
    )
    parser.add_argument(
        "-f",
        "--file",
        dest="file",
        default=None,
        metavar="PATH",
        help="Scan a local file: hash it and look up its SHA256",
    )
    parser.add_argument(
        "-a",
        "--artifact",
        dest="artifact",
        default=None,
        metavar="PATH",
        help="Analyze an artifact (TXT/LOG/CSV/PCAP/PCAPNG): extract, "
        "deduplicate, and look up every IOC it contains",
    )

    args = parser.parse_args()

    supplied = [args.ioc is not None, args.file is not None, args.artifact is not None]
    if sum(supplied) == 0:
        parser.error("provide an IOC, or use -f/--file <path>, or -a/--artifact <path>")
    if sum(supplied) > 1:
        parser.error("only one of: a positional IOC, -f/--file, -a/--artifact may be used at a time")

    return args


def run_scan(providers: list[BaseProvider], method_name: str, ioc: str) -> list[ProviderResult]:
    """
    Query all providers concurrently, showing a transient Rich progress
    indicator ("[i/N] ProviderName") while requests are in flight. The
    progress display is cleared as soon as scanning finishes, leaving
    only the final report on screen.
    """
    results: list[ProviderResult] = []
    total = len(providers)

    progress = ui.create_scan_progress(total)
    with progress:
        task_id = progress.add_task("scan", total=total, detail=f"[0/{total}]")

        with ThreadPoolExecutor(max_workers=total) as executor:
            futures = {
                executor.submit(query_provider, provider, method_name, ioc): provider
                for provider in providers
            }

            completed = 0
            for future in as_completed(futures):
                provider = futures[future]
                result = future.result()
                results.append(result)
                completed += 1
                progress.update(
                    task_id,
                    advance=1,
                    detail=f"[{completed}/{total}] {provider.name}",
                )

    # Preserve a stable, deterministic ordering (VT, OTX, ThreatFox) for display.
    order = {p.name: i for i, p in enumerate(providers)}
    results.sort(key=lambda r: order.get(r.provider, 99))
    return results


def calculate_verdict(results: list[ProviderResult]) -> tuple[int, str, int]:
    """
    Sum risk contributions from all providers, clamp to 0-100, and map
    to an overall verdict label. Also returns the number of sources
    that returned a positive hit (malicious/found).
    """
    risk_score = sum(r.risk_contribution for r in results)
    risk_score = max(0, min(risk_score, 100))

    hit_verdicts = {Verdict.MALICIOUS, Verdict.SUSPICIOUS, Verdict.FOUND}
    sources_hit = sum(1 for r in results if r.verdict in hit_verdicts)

    if risk_score <= 20:
        overall = "CLEAN"
    elif risk_score <= 50:
        overall = "SUSPICIOUS"
    else:
        overall = "HIGH RISK"

    return risk_score, overall, sources_hit


def build_recommendation(overall_verdict: str) -> list[str]:
    """
    Always returns a non-empty list of actionable bullet-point recommendations
    for the analyst, regardless of the overall verdict.
    """
    if overall_verdict == "HIGH RISK":
        return [
            "Block IOC immediately",
            "Investigate affected hosts",
            "Search historical logs",
            "Add IOC to SIEM watchlists",
            "Add IOC to Firewall/DNS blocklists",
        ]
    if overall_verdict == "SUSPICIOUS":
        return [
            "Perform manual investigation",
            "Search historical logs",
            "Monitor related hosts for follow-up activity",
        ]
    return ["No action required"]


def resolve_file_to_sha256(path: str) -> str | None:
    """
    Hash a local file, print its FILE INFORMATION panel, and return the
    SHA256 digest to feed into the normal lookup pipeline.

    All file-access errors are handled gracefully: on failure an error
    panel is shown and ``None`` is returned so the caller can exit cleanly
    without a traceback.

    Args:
        path: Path to the local file supplied via -f/--file.

    Returns:
        The file's SHA256 hex digest, or ``None`` if the file could not
        be read or hashed.
    """
    try:
        hashes = calculate_file_hashes(path)
    except (FileNotFoundError, IsADirectoryError, PermissionError, OSError) as exc:
        logger.error("Failed to hash file %s: %s", path, exc)
        ui.print_file_error(path, str(exc))
        return None

    ui.print_file_info(path, hashes)
    # Only the SHA256 is used for reputation lookups; MD5/SHA1 are shown
    # for reference but never queried against any provider.
    return hashes["sha256"]


def run_artifact_analysis(path: str, config, start_time: float) -> int:
    """
    Run the full artifact analysis pipeline for -a/--artifact and render
    its report. Returns the process exit code.
    """
    cache = IOCCache(db_path=CACHE_DB_PATH, ttl_seconds=CACHE_TTL_SECONDS)

    progress = ui.create_artifact_progress()
    try:
        with progress:
            progress.add_task("artifact", detail=f"Analyzing {path}...")
            rows, summary = analyze_artifact(path, config, cache)
    except UnsupportedArtifactError as exc:
        ui.print_unsupported_artifact(path, str(exc))
        return 1
    except ArtifactReadError as exc:
        ui.print_artifact_error(path, str(exc))
        return 1

    ui.print_artifact_summary(summary)
    ui.print_artifact_table(rows)

    all_results = [result for row in rows for result in row.results]
    ui.print_warnings(all_results)

    providers_used = sorted({result.provider for result in all_results})
    elapsed = time.perf_counter() - start_time
    ui.print_footer(elapsed, providers_used or ["No lookups performed"])

    return 0


def main() -> int:
    start_time = time.perf_counter()

    args = parse_args()

    ui.print_banner()

    config = load_config()

    if args.artifact is not None:
        return run_artifact_analysis(args.artifact, config, start_time)

    # A supplied file is converted to its SHA256, then handled by the exact
    # same pipeline as `python ioc_checker.py <sha256>`. Everything after
    # this point is identical for both direct-IOC and file inputs.
    if args.file is not None:
        sha256 = resolve_file_to_sha256(args.file)
        if sha256 is None:
            return 1
        ioc = sha256
    else:
        ioc = args.ioc.strip()

    ioc_type = detect_ioc_type(ioc)
    if ioc_type == IOCType.UNKNOWN:
        ui.print_unsupported_ioc(ioc)
        return 1

    ui.print_ioc_info(ioc, ioc_type)

    providers = get_providers_for_type(ioc_type, config)
    method_name = _LOOKUP_METHOD[ioc_type]

    results = run_scan(providers, method_name, ioc)
    ui.print_results_table(results)

    risk_score, overall_verdict, sources_hit = calculate_verdict(results)
    recommendation = build_recommendation(overall_verdict)

    ui.print_summary(
        risk_score=risk_score,
        overall_verdict=overall_verdict,
        sources_hit=sources_hit,
        total_sources=len(providers),
        recommendation=recommendation,
        ioc_type=ioc_type,
    )

    # Silent API health reporting: nothing is printed unless a provider
    # actually failed during this scan.
    ui.print_warnings(results)

    elapsed = time.perf_counter() - start_time
    ui.print_footer(elapsed, [p.name for p in providers])

    return 0


if __name__ == "__main__":
    sys.exit(main())
