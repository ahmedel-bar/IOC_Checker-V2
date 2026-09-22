"""
tests/test_extraction.py

Extraction tests: IPv4, Domain, URL, MD5, SHA1, SHA256.
IPv6 is intentionally never tested here - it is out of scope and must
never be extracted.
"""

from __future__ import annotations

from detector import IOCType

from artifacts._scan import scan_text_for_iocs


def _values_of_type(text: str, ioc_type: IOCType) -> list[str]:
    return [ioc.value for ioc in scan_text_for_iocs(text) if ioc.ioc_type == ioc_type]


def test_extracts_ipv4():
    text = "Connection from 185.10.20.30 observed."
    assert "185.10.20.30" in _values_of_type(text, IOCType.IPV4)


def test_extracts_domain():
    text = "Beacon to evil-domain.net was seen."
    assert "evil-domain.net" in _values_of_type(text, IOCType.DOMAIN)


def test_extracts_url_but_not_its_host_separately():
    """
    URLs now take full precedence over anything nested inside them - a
    domain used as a URL's host is no longer separately extracted (this
    changed from an earlier iteration where domains, unlike IPs, were
    still expanded from URLs; that expansion has since been removed so
    URLs and their nested IOCs behave consistently).
    """
    text = "Payload fetched from http://evil.com/malware.exe"
    urls = _values_of_type(text, IOCType.URL)
    domains = _values_of_type(text, IOCType.DOMAIN)
    assert "http://evil.com/malware.exe" in urls
    assert "evil.com" not in domains


def test_extracts_md5():
    text = "MD5: 44d88612fea8a8f36de82e1278abb02f"
    assert "44d88612fea8a8f36de82e1278abb02f" in _values_of_type(text, IOCType.MD5)


def test_extracts_sha1():
    text = "SHA1: aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
    assert "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d" in _values_of_type(text, IOCType.SHA1)


def test_extracts_sha256():
    text = "SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        in _values_of_type(text, IOCType.SHA256)
    )


def test_does_not_extract_ipv6():
    """IPv6 is intentionally unsupported and must never be extracted."""
    text = "Traffic to 2001:0db8:85a3:0000:0000:8a2e:0370:7334 was seen, alongside 8.8.8.8."
    all_iocs = list(scan_text_for_iocs(text))
    for ioc in all_iocs:
        assert "2001" not in ioc.value and ":" not in ioc.value
    assert "8.8.8.8" in _values_of_type(text, IOCType.IPV4)


def test_avoids_common_filename_false_positives():
    """
    Filenames whose extension isn't a real TLD are correctly rejected.
    Note: a small number of real ccTLDs (.md, .io, .sh, .ai, ...) happen
    to also be common file extensions - a string like "readme.md" is
    genuinely ambiguous by syntax alone (it's shaped exactly like a valid
    domain) and isn't covered by this test; see domain_validation.py's
    docstring for that known, accepted trade-off. Extensions that aren't
    real TLDs at all - the overwhelming majority, including every one
    named in this project's spec - are unambiguous and always rejected.
    """
    text = "See wp-cron.php, index.php, index.html, test.js, page.aspx, file.jsp, and payload.exe for details."
    domains = _values_of_type(text, IOCType.DOMAIN)
    for filename in ("wp-cron.php", "index.php", "index.html", "test.js", "page.aspx", "file.jsp", "payload.exe"):
        assert filename not in domains


def test_avoids_extracting_ip_from_unrelated_string():
    """A version-like or unrelated numeric string should not be misread as an IP."""
    text = "Build version 999.999.999.999 is not a real address."
    ips = _values_of_type(text, IOCType.IPV4)
    assert "999.999.999.999" not in ips


def test_ip_embedded_in_url_is_not_extracted_as_separate_ipv4():
    """
    The URL takes precedence over IOC patterns nested inside it: an IP
    used as a URL's host must not also become its own IPv4 occurrence.
    """
    text = "url which download from: http://105.224.244.218:59145/bin.sh"
    all_iocs = list(scan_text_for_iocs(text))

    urls = [i.value for i in all_iocs if i.ioc_type == IOCType.URL]
    ips = [i.value for i in all_iocs if i.ioc_type == IOCType.IPV4]

    assert "http://105.224.244.218:59145/bin.sh" in urls
    assert "105.224.244.218" not in ips


def test_ip_appearing_standalone_and_in_url_counts_standalone_once():
    """
    The exact scenario from the spec: the same IP appears both on its
    own and embedded in a URL. Only the standalone occurrence should
    produce an IPv4 IOC; the URL occurrence must not add to that count.
    """
    text = "attacker IP: 105.224.244.218\ndownload URL: http://105.224.244.218/file"
    all_iocs = list(scan_text_for_iocs(text))

    ip_occurrences = [i for i in all_iocs if i.ioc_type == IOCType.IPV4 and i.value == "105.224.244.218"]
    url_occurrences = [i for i in all_iocs if i.ioc_type == IOCType.URL]

    assert len(ip_occurrences) == 1
    assert len(url_occurrences) == 1
    assert url_occurrences[0].value == "http://105.224.244.218/file"


def test_domain_embedded_in_url_is_not_extracted_separately():
    """
    URLs take precedence over both IPs and domains nested inside them -
    a domain used as a URL's host is not additionally emitted as its own
    Domain IOC (matching the IPv4 case in
    test_ip_embedded_in_url_is_not_extracted_as_separate_ipv4).
    """
    text = "Payload fetched from http://evil.com/malware.exe"
    all_iocs = list(scan_text_for_iocs(text))
    domains = [i.value for i in all_iocs if i.ioc_type == IOCType.DOMAIN]
    assert "evil.com" not in domains


def test_domain_appearing_standalone_and_in_url_counts_standalone_once():
    """Mirrors the IPv4 case: only the standalone domain occurrence should be extracted."""
    text = "attacker domain: edit.yahoo.com\ndownload URL: http://edit.yahoo.com/config?login=test"
    all_iocs = list(scan_text_for_iocs(text))

    domain_occurrences = [i for i in all_iocs if i.ioc_type == IOCType.DOMAIN and i.value == "edit.yahoo.com"]
    url_occurrences = [i for i in all_iocs if i.ioc_type == IOCType.URL]

    assert len(domain_occurrences) == 1
    assert len(url_occurrences) == 1
    assert url_occurrences[0].value == "http://edit.yahoo.com/config?login=test"


def test_bare_ipv4_tagged_internal_at_extraction_time():
    text = "internal host 10.0.0.5 talked to external host 185.10.20.30"
    all_iocs = list(scan_text_for_iocs(text))

    internal_ip = next(i for i in all_iocs if i.value == "10.0.0.5")
    external_ip = next(i for i in all_iocs if i.value == "185.10.20.30")

    assert internal_ip.is_internal is True
    assert external_ip.is_internal is False


def test_arbitrary_free_form_text_no_required_structure():
    """
    Matches the spec's example directly: free-form human-written notes,
    no one-IOC-per-line or column structure required.
    """
    text = (
        "attacker ip: 94.231.206.248\n"
        "file downloaded from internet using powershell: b6445abdc7b00355a6a17179416049b1\n"
        "url which download from: http://105.224.244.218:59145/bin.sh\n"
        "another url: http://150.241.65.250:889/http_files/pito.ppc\n"
    )
    all_iocs = list(scan_text_for_iocs(text))
    values_by_type = {}
    for ioc in all_iocs:
        values_by_type.setdefault(ioc.ioc_type, set()).add(ioc.value)

    assert "94.231.206.248" in values_by_type[IOCType.IPV4]
    assert "b6445abdc7b00355a6a17179416049b1" in values_by_type[IOCType.MD5]
    assert "http://105.224.244.218:59145/bin.sh" in values_by_type[IOCType.URL]
    assert "http://150.241.65.250:889/http_files/pito.ppc" in values_by_type[IOCType.URL]
    # Neither URL's embedded IP host should appear as a separate IPv4 IOC.
    assert "105.224.244.218" not in values_by_type.get(IOCType.IPV4, set())
    assert "150.241.65.250" not in values_by_type.get(IOCType.IPV4, set())
