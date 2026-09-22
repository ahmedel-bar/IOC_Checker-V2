"""
artifacts/csv_extractor.py

Extracts IOCs from CSV artifacts without assuming any fixed schema: every
cell in every row is scanned using the same regex-based logic as
TextExtractor/LogExtractor (via artifacts._scan), so a URL, IP, domain, or
hash is found regardless of which column it happens to live in.

Named csv_extractor.py (not csv.py) purely to keep the module name
unambiguous for readers - Python 3's absolute-import model means a
same-named submodule wouldn't actually shadow the stdlib `csv` module we
import below, but the clearer name avoids any confusion either way.
"""

from __future__ import annotations

import csv
import io
from typing import Iterator

from artifacts._encoding import read_text_file
from artifacts._scan import scan_text_for_iocs
from artifacts.base import ArtifactExtractor, RawIOC


class CSVExtractor(ArtifactExtractor):
    def extract(self, path: str) -> Iterator[RawIOC]:
        # Read with encoding detection (BOM-aware) first, same as
        # TextExtractor, then hand the decoded text to csv.reader via an
        # in-memory buffer - this keeps CSV parsing correct for files
        # saved as UTF-16 (e.g. PowerShell's default redirection encoding)
        # instead of silently producing zero rows/cells.
        content = read_text_file(path)
        buffer = io.StringIO(content, newline="")

        try:
            sample = buffer.read(4096)
            buffer.seek(0)
            dialect = csv.Sniffer().sniff(sample, delimiters=",;\t")
        except csv.Error:
            dialect = csv.excel  # fall back to the standard comma dialect

        reader = csv.reader(buffer, dialect)
        for row in reader:
            for cell in row:
                if not cell or not cell.strip():
                    continue
                yield from scan_text_for_iocs(cell)
