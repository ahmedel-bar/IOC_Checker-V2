"""
artifacts/text.py

Extracts IOCs from plain text (.txt) artifacts.
"""

from __future__ import annotations

from typing import Iterator

from artifacts._encoding import read_text_file
from artifacts._scan import scan_text_for_iocs
from artifacts.base import ArtifactExtractor, RawIOC


class TextExtractor(ArtifactExtractor):
    def extract(self, path: str) -> Iterator[RawIOC]:
        content = read_text_file(path)
        yield from scan_text_for_iocs(content)
