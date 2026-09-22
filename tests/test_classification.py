"""
tests/test_classification.py

Classification tests: 0/1/2/3+ provider hit-count tiers, and the rule
that Not Found / Unavailable / Error results must never count as either
a hit or as "clean" by omission - they simply don't participate.
"""

from __future__ import annotations

from ioc.classifier import (
    CLEAN,
    MALICIOUS,
    MALICIOUS_HIGH_RISK,
    SUSPICIOUS,
    classify_by_hits,
    count_hits,
)
from utils import ProviderResult, Verdict


def _result(verdict: Verdict) -> ProviderResult:
    return ProviderResult(provider="TestProvider", verdict=verdict, details="")


def test_zero_hits_is_clean():
    assert classify_by_hits(0) == CLEAN


def test_one_hit_is_suspicious():
    assert classify_by_hits(1) == SUSPICIOUS


def test_two_hits_is_malicious():
    assert classify_by_hits(2) == MALICIOUS


def test_three_or_more_hits_is_malicious_high_risk():
    assert classify_by_hits(3) == MALICIOUS_HIGH_RISK
    assert classify_by_hits(7) == MALICIOUS_HIGH_RISK


def test_count_hits_counts_malicious_suspicious_and_found():
    results = [
        _result(Verdict.MALICIOUS),
        _result(Verdict.SUSPICIOUS),
        _result(Verdict.FOUND),
    ]
    assert count_hits(results) == 3


def test_not_found_never_counts_as_a_hit():
    results = [_result(Verdict.NOT_FOUND)]
    assert count_hits(results) == 0
    assert classify_by_hits(count_hits(results)) == CLEAN


def test_error_never_counts_as_a_hit():
    results = [_result(Verdict.ERROR)]
    assert count_hits(results) == 0


def test_unsupported_never_counts_as_a_hit():
    results = [_result(Verdict.UNSUPPORTED)]
    assert count_hits(results) == 0


def test_mixed_errors_and_hits_only_count_real_hits():
    """
    Not Found / Error must never be silently treated as Clean or as a
    hit - they should simply be excluded from the hit count while a
    genuine malicious/suspicious/found verdict from another provider
    still counts normally.
    """
    results = [
        _result(Verdict.ERROR),
        _result(Verdict.NOT_FOUND),
        _result(Verdict.MALICIOUS),
    ]
    assert count_hits(results) == 1
    assert classify_by_hits(count_hits(results)) == SUSPICIOUS
