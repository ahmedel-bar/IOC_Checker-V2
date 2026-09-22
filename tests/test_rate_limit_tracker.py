"""
tests/test_rate_limit_tracker.py

The per-run rate-limit circuit breaker (providers.http_utils.RateLimitTracker):
once a provider is marked rate-limited, further lookups against it should
be skipped without any additional request, while other providers stay
unaffected.
"""

from __future__ import annotations

from providers.http_utils import RateLimitTracker


def test_provider_not_limited_by_default():
    tracker = RateLimitTracker()
    assert tracker.is_limited("VirusTotal") is False


def test_marking_a_provider_limits_only_that_provider():
    tracker = RateLimitTracker()
    tracker.mark_limited("VirusTotal")

    assert tracker.is_limited("VirusTotal") is True
    assert tracker.is_limited("AbuseIPDB") is False


def test_marking_is_idempotent():
    tracker = RateLimitTracker()
    tracker.mark_limited("VirusTotal")
    tracker.mark_limited("VirusTotal")
    assert tracker.is_limited("VirusTotal") is True


def test_tracker_instances_are_independent():
    """Each analysis run gets a fresh tracker - no cross-run state leakage."""
    tracker1 = RateLimitTracker()
    tracker2 = RateLimitTracker()

    tracker1.mark_limited("VirusTotal")

    assert tracker1.is_limited("VirusTotal") is True
    assert tracker2.is_limited("VirusTotal") is False
