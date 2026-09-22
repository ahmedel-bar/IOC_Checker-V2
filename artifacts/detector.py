"""
artifacts/detector.py

Determines the type of an uploaded artifact file.

PCAP/PCAPNG are detected reliably via their binary magic-number file
signature, which never changes regardless of the file's extension. Plain
text formats (TXT/LOG/CSV) don't have a reliable binary signature, so they
are identified by extension, with a light content heuristic to catch CSV
files that were saved without a ".csv" extension.
"""

from __future__ import annotations

import csv
import io
from enum import Enum
from pathlib import Path

# Classic pcap magic numbers (both byte orders, both micro/nanosecond
# timestamp variants).
_PCAP_MAGIC_NUMBERS = {
    b"\xd4\xc3\xb2\xa1",  # little-endian, microsecond
    b"\xa1\xb2\xc3\xd4",  # big-endian, microsecond
    b"\x4d\x3c\xb2\xa1",  # little-endian, nanosecond
    b"\xa1\xb2\x3c\x4d",  # big-endian, nanosecond
}
# pcapng Section Header Block magic number.
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

_TEXT_EXTENSIONS = {".txt", ".log", ".csv"}


class ArtifactType(str, Enum):
    TXT = "TXT"
    LOG = "LOG"
    CSV = "CSV"
    PCAP = "PCAP"
    PCAPNG = "PCAPNG"
    UNKNOWN = "UNKNOWN"


def _looks_like_csv(sample: str) -> bool:
    """
    Best-effort content heuristic for CSV files saved without a .csv
    extension: if the csv module's sniffer can confidently identify a
    delimiter across a small sample, and at least two lines share the
    same field count, treat it as CSV.
    """
    sample = sample.strip()
    if not sample:
        return False
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t")
    except csv.Error:
        return False

    reader = csv.reader(io.StringIO(sample), dialect)
    rows = [row for row in reader if row]
    if len(rows) < 2:
        return False
    field_counts = {len(row) for row in rows}
    # Consistent column count across rows and more than one column is a
    # strong signal of tabular/CSV data rather than free-form text.
    return len(field_counts) == 1 and next(iter(field_counts)) > 1


def detect_artifact_type(path: str) -> ArtifactType:
    """
    Inspect the file at ``path`` and classify it as one of the supported
    ArtifactType values. Binary pcap/pcapng formats are detected via file
    signature (reliable regardless of extension); text formats fall back
    to extension, with a CSV content-sniffing heuristic as a bonus check.
    """
    file_path = Path(path)

    with open(path, "rb") as handle:
        header = handle.read(4)

    if header == _PCAPNG_MAGIC:
        return ArtifactType.PCAPNG
    if header in _PCAP_MAGIC_NUMBERS:
        return ArtifactType.PCAP

    suffix = file_path.suffix.lower()
    if suffix == ".pcapng":
        return ArtifactType.PCAPNG
    if suffix == ".pcap":
        return ArtifactType.PCAP

    if suffix in _TEXT_EXTENSIONS or suffix == "":
        # Try to read a small sample as text; if it isn't decodable as
        # UTF-8 (or Latin-1 fallback), it's not one of our text formats.
        try:
            with open(path, "r", encoding="utf-8", errors="strict") as handle:
                sample = handle.read(4096)
        except (UnicodeDecodeError, OSError):
            try:
                with open(path, "r", encoding="latin-1", errors="strict") as handle:
                    sample = handle.read(4096)
            except OSError:
                return ArtifactType.UNKNOWN

        if suffix == ".csv":
            return ArtifactType.CSV
        if suffix == ".log":
            return ArtifactType.LOG
        if suffix == ".txt":
            return ArtifactType.TXT

        # No recognized extension - fall back to content sniffing.
        if _looks_like_csv(sample):
            return ArtifactType.CSV
        return ArtifactType.TXT

    return ArtifactType.UNKNOWN
