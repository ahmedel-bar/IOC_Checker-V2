"""
tests/test_domain_validation.py

domain_validation.is_valid_domain: generic, TLD-based domain vs. filename
distinction, replacing the old file-extension blacklist. Uses the exact
test values named in the project spec.
"""

from __future__ import annotations

from domain_validation import is_valid_domain


def test_rejects_filenames_named_in_spec():
    for filename in ("wp-cron.php", "index.php", "index.html", "test.js", "page.aspx", "file.jsp"):
        assert is_valid_domain(filename) is False, filename


def test_accepts_real_domains_named_in_spec():
    for domain in ("evil.example.com", "proxyjudge1.proxyfire.net", "www.wantsfly.com", "help.naver.com"):
        assert is_valid_domain(domain) is True, domain


def test_accepts_simple_two_label_domain():
    assert is_valid_domain("edit.yahoo.com") is True


def test_rejects_value_with_no_dot():
    assert is_valid_domain("localhost") is False


def test_rejects_empty_string():
    assert is_valid_domain("") is False
