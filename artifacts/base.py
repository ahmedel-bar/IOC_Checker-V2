"""
artifacts/base.py

Shared extraction primitives. Every artifact-specific extractor
(TextExtractor, LogExtractor, CSVExtractor, PCAPExtractor) implements
the same ArtifactExtractor interface and yields RawIOC instances.

Important: extractors ONLY discover IOCs. They never normalize, dedupe,
count occurrences, filter internal IPs, or perform lookups - that all
happens in later pipeline stages (see ioc/aggregator.py and
artifact_pipeline.py). This keeps extraction logic reusable for future
artifact types (.eml, STIX, MISP, JSON, ...) without touching the lookup
or provider layers.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Iterator

from detector import IOCType


@dataclass(frozen=True)
class RawIOC:
    """
    A single, not-yet-normalized IOC occurrence found during extraction.

    `is_internal` is only meaningful for IOCType.IPV4 (always False for
    every other type). It's computed by the extractor at the moment the
    address is found (see ip_classification.is_internal_ipv4), not
    derived later - this is what lets the pipeline skip private/reserved
    addresses as lookup candidates from the very start, rather than
    creating a full lookup-candidate object and filtering it out
    afterwards.
    """

    value: str
    ioc_type: IOCType
    is_internal: bool = False


class ArtifactExtractor(ABC):
    """Common interface every artifact-type-specific extractor implements."""

    @abstractmethod
    def extract(self, path: str) -> Iterator[RawIOC]:
        """
        Yield one RawIOC per occurrence found in the artifact at ``path``.
        The same IOC appearing multiple times should be yielded multiple
        times - deduplication and occurrence counting happen later.
        """
        ...
