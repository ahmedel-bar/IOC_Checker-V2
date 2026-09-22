"""
artifacts/pcap.py

Extracts IOCs from PCAP/PCAPNG network capture artifacts using dpkt - a
lightweight, pure-Python packet parsing library with no heavy compiled
dependencies (chosen over scapy specifically to avoid adding a much
larger dependency for what is fundamentally a read-only parsing task).

Extracts, where available, per packet:
    - IPv4 source/destination addresses (IPv6 is intentionally skipped)
    - DNS queried domains
    - HTTP Host header + request URL
    - TLS ClientHello SNI (Server Name Indication) hostname

Every DNS/SNI/HTTP-Host-derived Domain candidate is validated through
domain_validation.is_valid_domain() - the same canonical classifier used
by the direct CLI (detector.py) and text-based extraction
(artifacts/_scan.py) - before being yielded as a Domain RawIOC. This
matters even though these values come from structured protocol fields
rather than free-text regex matching: a DNS query name, SNI hostname, or
HTTP Host header can still be garbage (malformed packets, DNS-tunneling
malware using single-letter or truncated subdomains for beaconing,
fuzzing/scanning traffic, etc.), and without this check such a value
would reach providers as a "Domain" while the exact same string typed
directly on the command line would correctly be rejected as unsupported
- the same class of inconsistency this project's canonical classifier
exists to prevent everywhere else.

Every packet is parsed inside its own try/except so a single malformed,
truncated, or unsupported-protocol packet can never abort the scan of the
rest of the capture.
"""

from __future__ import annotations

import logging
import struct
from typing import Iterator

import dpkt

from artifacts.base import ArtifactExtractor, RawIOC
from detector import IOCType
from domain_validation import is_valid_domain
from ip_classification import is_internal_ipv4

logger = logging.getLogger("ioc_checker")

_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

# dpkt link-type constants we know how to unwrap down to an IP layer.
_DLT_EN10MB = 1
_DLT_RAW = 101
_DLT_LINUX_SLL = 113


def _iter_packets(path: str) -> Iterator[tuple[float, bytes, int]]:
    """Yield (timestamp, raw_bytes, linktype) for every packet in the capture."""
    with open(path, "rb") as handle:
        header = handle.read(4)
        handle.seek(0)

        if header == _PCAPNG_MAGIC:
            reader = dpkt.pcapng.Reader(handle)
        else:
            reader = dpkt.pcap.Reader(handle)

        linktype = reader.datalink()
        for ts, buf in reader:
            yield ts, buf, linktype


def _unwrap_to_ip(buf: bytes, linktype: int):
    """Best-effort unwrap of a raw frame down to a dpkt.ip.IP instance (or None)."""
    if linktype == _DLT_EN10MB:
        frame = dpkt.ethernet.Ethernet(buf)
        data = frame.data
    elif linktype == _DLT_LINUX_SLL:
        frame = dpkt.sll.SLL(buf)
        data = frame.data
    elif linktype == _DLT_RAW:
        data = dpkt.ip.IP(buf)
    else:
        # Unknown/unsupported link type - nothing we can reliably unwrap.
        return None

    if isinstance(data, dpkt.ip.IP):
        return data
    return None


def _extract_sni(client_hello_payload: bytes) -> str | None:
    """
    Best-effort manual parse of a TLS ClientHello record for the SNI
    (server_name) extension. Returns the hostname, or None if this isn't
    a parseable ClientHello or it has no SNI extension.
    """
    try:
        # TLS record header: type(1) version(2) length(2)
        if len(client_hello_payload) < 6 or client_hello_payload[0] != 0x16:
            return None
        pos = 5  # skip record header

        # Handshake header: msg_type(1) length(3)
        if client_hello_payload[pos] != 0x01:  # ClientHello
            return None
        pos += 4

        pos += 2  # client_version
        pos += 32  # random

        session_id_len = client_hello_payload[pos]
        pos += 1 + session_id_len

        cipher_suites_len = struct.unpack("!H", client_hello_payload[pos:pos + 2])[0]
        pos += 2 + cipher_suites_len

        compression_methods_len = client_hello_payload[pos]
        pos += 1 + compression_methods_len

        if pos >= len(client_hello_payload):
            return None

        extensions_len = struct.unpack("!H", client_hello_payload[pos:pos + 2])[0]
        pos += 2
        extensions_end = pos + extensions_len

        while pos < extensions_end:
            ext_type = struct.unpack("!H", client_hello_payload[pos:pos + 2])[0]
            ext_len = struct.unpack("!H", client_hello_payload[pos + 2:pos + 4])[0]
            ext_data_start = pos + 4

            if ext_type == 0x0000:  # server_name
                sni_list_len = struct.unpack(
                    "!H", client_hello_payload[ext_data_start:ext_data_start + 2]
                )[0]
                sni_pos = ext_data_start + 2
                sni_list_end = sni_pos + sni_list_len
                while sni_pos < sni_list_end:
                    name_type = client_hello_payload[sni_pos]
                    name_len = struct.unpack(
                        "!H", client_hello_payload[sni_pos + 1:sni_pos + 3]
                    )[0]
                    name_start = sni_pos + 3
                    if name_type == 0x00:  # host_name
                        return client_hello_payload[name_start:name_start + name_len].decode(
                            "ascii", errors="ignore"
                        )
                    sni_pos = name_start + name_len

            pos = ext_data_start + ext_len

    except (IndexError, struct.error, UnicodeDecodeError):
        return None
    return None


def _extract_http_host_and_url(tcp_payload: bytes) -> tuple[str | None, str | None]:
    """Best-effort HTTP request parse -> (host, full_url)."""
    try:
        request = dpkt.http.Request(tcp_payload)
    except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError, ValueError):
        return None, None

    host = request.headers.get("host")
    if not host:
        return None, None

    uri = request.uri if request.uri.startswith("/") else f"/{request.uri}"
    return host, f"http://{host}{uri}"


def _validated_domain(hostname: str) -> str | None:
    """
    Run a protocol-derived hostname (DNS query name, TLS SNI, HTTP Host
    header) through the canonical domain classifier before it's allowed
    to become a Domain IOC. Strips a trailing port (a Host header may
    include one, e.g. "evil.com:8080") since is_valid_domain expects a
    bare hostname - the port itself carries no separate IOC value here.
    Returns the validated hostname, or None if it doesn't pass.
    """
    if not hostname:
        return None
    bare_host = hostname.split(":", 1)[0].strip()
    if is_valid_domain(bare_host):
        return bare_host
    return None


class PCAPExtractor(ArtifactExtractor):
    def extract(self, path: str) -> Iterator[RawIOC]:
        try:
            packets = list(_iter_packets(path))
        except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError, struct.error, OSError, ValueError) as exc:
            logger.error("Failed to open capture file %s: %s", path, exc)
            raise ValueError(f"Corrupted or unreadable capture file: {exc}") from exc

        for ts, buf, linktype in packets:
            try:
                ip = _unwrap_to_ip(buf, linktype)
            except Exception as exc:  # noqa: BLE001 - a single bad packet must not abort the scan
                logger.debug("Skipping malformed packet: %s", exc)
                continue

            if ip is None:
                continue

            try:
                src = dpkt.utils.inet_to_str(ip.src)
                dst = dpkt.utils.inet_to_str(ip.dst)
                if src:
                    yield RawIOC(value=src, ioc_type=IOCType.IPV4, is_internal=is_internal_ipv4(src))
                if dst:
                    yield RawIOC(value=dst, ioc_type=IOCType.IPV4, is_internal=is_internal_ipv4(dst))
            except (ValueError, AttributeError):
                pass

            try:
                yield from self._extract_transport_layer(ip)
            except Exception as exc:  # noqa: BLE001
                logger.debug("Skipping unparseable transport payload: %s", exc)
                continue

    def _extract_transport_layer(self, ip) -> Iterator[RawIOC]:
        transport = ip.data

        if isinstance(transport, dpkt.udp.UDP):
            if transport.sport == 53 or transport.dport == 53:
                yield from self._extract_dns(transport.data)

        elif isinstance(transport, dpkt.tcp.TCP):
            payload = transport.data
            if not payload:
                return

            if transport.sport == 443 or transport.dport == 443:
                sni = _extract_sni(payload)
                validated_sni = _validated_domain(sni) if sni else None
                if validated_sni:
                    yield RawIOC(value=validated_sni, ioc_type=IOCType.DOMAIN)
                return

            if transport.sport == 80 or transport.dport == 80:
                host, url = _extract_http_host_and_url(payload)
                validated_host = _validated_domain(host) if host else None
                if validated_host:
                    yield RawIOC(value=validated_host, ioc_type=IOCType.DOMAIN)
                if url:
                    yield RawIOC(value=url, ioc_type=IOCType.URL)

    def _extract_dns(self, udp_payload: bytes) -> Iterator[RawIOC]:
        try:
            dns = dpkt.dns.DNS(udp_payload)
        except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
            return

        for question in dns.qd:
            name = question.name
            validated_name = _validated_domain(name) if name else None
            if validated_name:
                yield RawIOC(value=validated_name, ioc_type=IOCType.DOMAIN)
