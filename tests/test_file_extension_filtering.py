"""
tests/test_file_extension_filtering.py

Standalone filenames must not be classified as Domains, but this
filtering must never apply to URLs (a URL's own path/host may legitimately
contain a file-extension-looking string). Covers the exact test cases
from the project spec.
"""

from __future__ import annotations

from artifacts._scan import scan_text_for_iocs
from detector import IOCType, detect_ioc_type
from domain_validation import is_valid_domain
from file_extensions import has_known_file_extension

_STANDALONE_FILENAMES = [
    "settings.py",
    "forms.py",
    "proxy.py",
    "tests.py",
    "runme.sh",
    "script.ps1",
    "wp-cron.php",
    "index.php",
    "index.html",
    "test.js",
    "malware.exe",
    "report.pdf",
]

_VALID_STANDALONE_DOMAINS = [
    "domain.org",
    "evil.com",
    "example.net",
    "proxyjudge1.proxyfire.net",
    "www.wantsfly.com",
    "help.naver.com",
]

_URLS_WITH_FILE_EXTENSION_LOOKING_HOSTS_OR_PATHS = [
    "http://105.224.244.218:8080/test",
    "http://evil.com/login",
    "http://example.py/file.exe",
    "http://evil.com/download/malware.exe",
    "http://example.com/config.php",
]


# --- file_extensions.py itself -----------------------------------------

def test_has_known_file_extension_detects_spec_filenames():
    for filename in _STANDALONE_FILENAMES:
        assert has_known_file_extension(filename) is True, filename


def test_has_known_file_extension_false_for_no_dot():
    assert has_known_file_extension("localhost") is False


def test_known_extensions_do_not_include_dangerous_tld_collisions():
    """
    'com' and 'app' are deliberately excluded from the extension list even
    though DOS .com executables and .app-style naming exist in principle -
    .com is the single most common real TLD and including it would break
    ordinary domains like "evil.com".
    """
    from file_extensions import KNOWN_FILE_EXTENSIONS
    assert "com" not in KNOWN_FILE_EXTENSIONS


# --- domain_validation.py integration -----------------------------------

def test_is_valid_domain_rejects_all_spec_filenames():
    for filename in _STANDALONE_FILENAMES:
        assert is_valid_domain(filename) is False, filename


def test_is_valid_domain_accepts_all_spec_domains():
    for domain in _VALID_STANDALONE_DOMAINS:
        assert is_valid_domain(domain) is True, domain


# --- Full extraction pipeline (artifacts/_scan.py) -----------------------

def test_standalone_filenames_never_extracted_as_domains():
    text = "\n".join(_STANDALONE_FILENAMES)
    domains = [i.value for i in scan_text_for_iocs(text) if i.ioc_type == IOCType.DOMAIN]
    for filename in _STANDALONE_FILENAMES:
        assert filename not in domains


def test_standalone_domains_still_extracted():
    text = "\n".join(_VALID_STANDALONE_DOMAINS)
    domains = {i.value for i in scan_text_for_iocs(text) if i.ioc_type == IOCType.DOMAIN}
    for domain in _VALID_STANDALONE_DOMAINS:
        assert domain in domains


def test_file_extension_filtering_never_applied_to_urls():
    """
    The critical requirement: a URL must remain a URL (and its embedded
    host/path never separately suppressed) even when its host or path
    looks exactly like a filtered filename extension.
    """
    text = "\n".join(_URLS_WITH_FILE_EXTENSION_LOOKING_HOSTS_OR_PATHS)
    all_iocs = list(scan_text_for_iocs(text))
    urls = [i.value for i in all_iocs if i.ioc_type == IOCType.URL]

    for url in _URLS_WITH_FILE_EXTENSION_LOOKING_HOSTS_OR_PATHS:
        assert url in urls

    # None of these should produce any Domain or extra IPv4 IOC - each
    # URL occurrence should contribute only the URL itself.
    domains = [i for i in all_iocs if i.ioc_type == IOCType.DOMAIN]
    ipv4s = [i for i in all_iocs if i.ioc_type == IOCType.IPV4]
    assert domains == []
    assert ipv4s == []


def test_url_and_standalone_domain_combined_occurrence_counts():
    """
    Exact scenario from the spec: a URL and a standalone occurrence of
    the same domain should each count as exactly one occurrence, with
    the URL's embedded domain never inflating the standalone count.
    """
    text = "http://evil.com/login\nevil.com\n"
    all_iocs = list(scan_text_for_iocs(text))
    urls = [i for i in all_iocs if i.ioc_type == IOCType.URL]
    domains = [i for i in all_iocs if i.ioc_type == IOCType.DOMAIN]

    assert len(urls) == 1
    assert len(domains) == 1
    assert domains[0].value == "evil.com"


# --- Direct CLI path (detector.py) consistency ---------------------------

def test_direct_cli_rejects_standalone_filenames():
    for filename in _STANDALONE_FILENAMES:
        assert detect_ioc_type(filename) == IOCType.UNKNOWN, filename


def test_direct_cli_accepts_standalone_domains():
    for domain in _VALID_STANDALONE_DOMAINS:
        assert detect_ioc_type(domain) == IOCType.DOMAIN, domain
