"""
artifacts/log.py

Extracts IOCs from log (.log) artifacts. Log files are free-form text for
extraction purposes, so this simply reuses TextExtractor rather than
duplicating the scanning logic. Kept as its own class (rather than a bare
alias) so the artifact-type -> extractor registry stays explicit and easy
to extend independently in the future if log-specific parsing is ever
needed (e.g. structured log formats).
"""

from __future__ import annotations

from artifacts.text import TextExtractor


class LogExtractor(TextExtractor):
    """Identical to TextExtractor today; kept distinct for future log-specific parsing."""
