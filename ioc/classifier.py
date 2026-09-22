"""
ioc/classifier.py

Final per-IOC classification for the artifact analysis report, based on
how many providers returned a positive hit (malicious/suspicious/found).

This is intentionally a different rule set from the single-IOC risk-score
based classification used elsewhere in the project (ioc_checker.py's
calculate_verdict): the artifact feature classifies by provider hit
*count* rather than a weighted risk score, as specified. Reuses the
existing Verdict enum rather than inventing a parallel status enum.
"""

from __future__ import annotations

from utils import ProviderResult, Verdict

# A "hit" is any provider result that represents a positive signal. This
# mirrors the hit-detection set already used by the direct single-IOC
# pipeline (see ioc_checker.calculate_verdict), so a ThreatFox/MalwareBazaar
# "FOUND" match counts the same way here as it does there - not found,
# unavailable, and errors never count as a hit.
_HIT_VERDICTS = {Verdict.MALICIOUS, Verdict.SUSPICIOUS, Verdict.FOUND}

CLEAN = "CLEAN"
SUSPICIOUS = "SUSPICIOUS"
MALICIOUS = "MALICIOUS"
MALICIOUS_HIGH_RISK = "MALICIOUS (HIGH RISK)"

# Used for sorting the final report: lower number = higher priority.
CLASSIFICATION_PRIORITY = {
    MALICIOUS_HIGH_RISK: 0,
    MALICIOUS: 1,
    SUSPICIOUS: 2,
    CLEAN: 3,
}


def count_hits(results: list[ProviderResult]) -> int:
    """Count how many provider results are a positive malicious/suspicious hit."""
    return sum(1 for r in results if r.verdict in _HIT_VERDICTS)


def classify_by_hits(hit_count: int) -> str:
    """
    Map a provider hit count to the artifact classification tiers:

        0 hits  -> CLEAN
        1 hit   -> SUSPICIOUS
        2 hits  -> MALICIOUS
        3+ hits -> MALICIOUS (HIGH RISK)
    """
    if hit_count <= 0:
        return CLEAN
    if hit_count == 1:
        return SUSPICIOUS
    if hit_count == 2:
        return MALICIOUS
    return MALICIOUS_HIGH_RISK
