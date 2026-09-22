"""
tests/test_artifact_detector.py

Artifact type detection: signature-based for PCAP/PCAPNG, extension-based
(with content sniffing) for TXT/LOG/CSV, and a clear UNKNOWN result for
unsupported types.
"""

from __future__ import annotations

import struct

from artifacts.detector import ArtifactType, detect_artifact_type


def test_detects_txt_by_extension(tmp_path):
    path = tmp_path / "notes.txt"
    path.write_text("just some notes, no IOCs here")
    assert detect_artifact_type(str(path)) == ArtifactType.TXT


def test_detects_log_by_extension(tmp_path):
    path = tmp_path / "access.log"
    path.write_text("192.168.1.1 - - [10/Oct/2024] GET /\n")
    assert detect_artifact_type(str(path)) == ArtifactType.LOG


def test_detects_csv_by_extension(tmp_path):
    path = tmp_path / "iocs.csv"
    path.write_text("ip,domain\n1.2.3.4,evil.com\n")
    assert detect_artifact_type(str(path)) == ArtifactType.CSV


def test_detects_csv_by_content_without_extension(tmp_path):
    path = tmp_path / "data_export"
    path.write_text("timestamp,src_ip,dst_ip\n12:30,10.0.0.5,185.10.20.30\n12:31,10.0.0.6,1.2.3.4\n")
    assert detect_artifact_type(str(path)) == ArtifactType.CSV


def test_detects_pcap_by_signature_regardless_of_extension(tmp_path):
    # Classic pcap magic number, little-endian microsecond variant.
    path = tmp_path / "capture.bin"
    path.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
    assert detect_artifact_type(str(path)) == ArtifactType.PCAP


def test_detects_pcapng_by_signature(tmp_path):
    path = tmp_path / "capture.dat"
    path.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 20)
    assert detect_artifact_type(str(path)) == ArtifactType.PCAPNG


def test_unsupported_extension_is_unknown(tmp_path):
    path = tmp_path / "sample.exe"
    path.write_bytes(b"MZ\x90\x00" + b"\x00" * 20)
    assert detect_artifact_type(str(path)) == ArtifactType.UNKNOWN
