"""
ioc/models.py

Data structures shared across the normalization, aggregation, and
classification stages of the artifact analysis pipeline.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from detector import IOCType
from utils import ProviderResult


@dataclass
class AggregatedIOC:
    """A single normalized, deduplicated IOC with its occurrence count."""

    value: str
    ioc_type: IOCType
    occurrences: int = 0
    is_internal: bool = False


@dataclass
class IOCReportRow:
    """One row of the final artifact IOC report, after lookups + classification."""

    ioc: str
    ioc_type: IOCType
    occurrences: int
    classification: str
    hit_count: int
    applicable_count: int
    results: list[ProviderResult] = field(default_factory=list)
    # Value of the parent URL this IOC was derived from (its hostname),
    # or None for a normal, top-level IOC. See ioc/url_children.py. A
    # child IOC's own reputation/classification/results above are always
    # computed completely independently of its parent's - this field is
    # purely relationship metadata for report rendering (ui.py).
    parent: str | None = None
