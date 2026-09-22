"""
tests/test_pcap_domain_validation.py

Regression coverage for the bug where PCAP's DNS query name, TLS SNI, and
HTTP Host header extraction paths assigned IOCType.DOMAIN directly from
raw protocol data without validating through the canonical classifier
(domain_validation.is_valid_domain, the same one used by detector.py and
artifacts/_scan.py). A garbage/malformed DNS query name like "c" or
"th.bing.c" (DNS-tunneling malware, fuzzing traffic, malformed packets)
would previously reach providers as a "Domain" while the exact same
value typed on the direct CLI was correctly rejected as unsupported.
"""

from __future__ import annotations

from artifacts.pcap import PCAPExtractor, _validated_domain
from detector import detect_ioc_type, IOCType

_INVALID_VALUES = ["c", "xpaywa", "th.bing.c", "173.46.81.201", "settings.py", "wp-cron.php"]
_VALID_DOMAINS = ["evil.example.com", "domain.org", "example.net", "domain.xyz"]


def test_validated_domain_rejects_invalid_values():
    for value in _INVALID_VALUES:
        assert _validated_domain(value) is None, value


def test_validated_domain_accepts_real_domains():
    for value in _VALID_DOMAINS:
        assert _validated_domain(value) == value, value


def test_validated_domain_strips_port_before_validating():
    assert _validated_domain("evil.com:8080") == "evil.com"
    assert _validated_domain("c:443") is None


def test_validated_domain_agrees_with_direct_cli_classifier():
    """
    The core regression: PCAP's protocol-derived domain validation must
    reach the same accept/reject decision as the direct CLI path for
    every test value - there must be no separate, weaker classifier.
    """
    for value in _INVALID_VALUES + _VALID_DOMAINS:
        cli_says_domain = detect_ioc_type(value) == IOCType.DOMAIN
        pcap_says_domain = _validated_domain(value) is not None
        assert cli_says_domain == pcap_says_domain, (
            f"{value}: CLI={cli_says_domain} PCAP={pcap_says_domain}"
        )


def test_validated_domain_none_for_empty_or_none():
    assert _validated_domain("") is None
    assert _validated_domain(None) is None


def test_pcap_extractor_excludes_invalid_dns_query_names(tmp_path):
    """Full-pipeline check: PCAPExtractor.extract() must never yield a
    Domain RawIOC for a garbage DNS query name, using a real synthetic
    capture (not just the helper function in isolation)."""
    import socket

    import dpkt

    def build_eth(ip_pkt):
        eth = dpkt.ethernet.Ethernet()
        eth.src = b"\x00\x11\x22\x33\x44\x55"
        eth.dst = b"\x66\x77\x88\x99\xaa\xbb"
        eth.type = dpkt.ethernet.ETH_TYPE_IP
        eth.data = ip_pkt
        return bytes(eth)

    def make_ip(src, dst, proto_data, proto):
        ip = dpkt.ip.IP()
        ip.v = 4
        ip.hl = 5
        ip.src = socket.inet_aton(src)
        ip.dst = socket.inet_aton(dst)
        ip.p = proto
        ip.data = proto_data
        ip.len = 20 + len(bytes(proto_data))
        return ip

    def make_dns_query(qname):
        dns = dpkt.dns.DNS()
        dns.qd = [dpkt.dns.DNS.Q(name=qname, type=dpkt.dns.DNS_A, cls=dpkt.dns.DNS_IN)]
        dns.qr = dpkt.dns.DNS_Q
        udp = dpkt.udp.UDP(sport=53421, dport=53, data=bytes(dns))
        udp.ulen = 8 + len(bytes(dns))
        return udp

    pcap_path = tmp_path / "garbage_dns.pcap"
    with open(pcap_path, "wb") as f:
        writer = dpkt.pcap.Writer(f)
        for qname in ["c", "th.bing.c", "xpaywa", "evil.example.com"]:
            udp = make_dns_query(qname)
            ip = make_ip("185.10.20.30", "10.0.0.5", udp, dpkt.ip.IP_PROTO_UDP)
            writer.writepkt(build_eth(ip), ts=1000.0)
        writer.close()

    results = list(PCAPExtractor().extract(str(pcap_path)))
    domains = [r.value for r in results if r.ioc_type == IOCType.DOMAIN]

    assert domains == ["evil.example.com"]
