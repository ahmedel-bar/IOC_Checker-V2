"""
tests/test_csv_extractor.py

CSV extraction: schema-agnostic, extracts from every cell, matches the
exact example given in the project spec.
"""

from __future__ import annotations

from artifacts.csv_extractor import CSVExtractor
from detector import IOCType


def test_csv_spec_example(tmp_path):
    path = tmp_path / "sample.csv"
    path.write_text(
        "timestamp,src_ip,dst_ip,url\n"
        "12:30,10.0.0.5,185.10.20.30,http://evil.com\n"
    )

    results = list(CSVExtractor().extract(str(path)))
    values_by_type = {}
    for r in results:
        values_by_type.setdefault(r.ioc_type, set()).add(r.value)

    assert "10.0.0.5" in values_by_type[IOCType.IPV4]
    assert "185.10.20.30" in values_by_type[IOCType.IPV4]
    assert "http://evil.com" in values_by_type[IOCType.URL]
    # The URL's host is no longer separately expanded into a Domain IOC -
    # URLs take full precedence over anything nested inside them.
    assert IOCType.DOMAIN not in values_by_type


def test_csv_does_not_assume_fixed_column_order(tmp_path):
    """IOCs should be found regardless of which column they're in."""
    path = tmp_path / "reordered.csv"
    path.write_text(
        "url,notes,src_ip\n"
        "http://evil.com,suspicious traffic,10.0.0.5\n"
    )

    results = list(CSVExtractor().extract(str(path)))
    values = {r.value for r in results}
    assert "http://evil.com" in values
    assert "10.0.0.5" in values


def test_csv_ignores_ipv6_cells(tmp_path):
    path = tmp_path / "with_ipv6.csv"
    path.write_text(
        "ip\n"
        "2001:0db8:85a3:0000:0000:8a2e:0370:7334\n"
        "8.8.8.8\n"
    )

    results = list(CSVExtractor().extract(str(path)))
    values = {r.value for r in results}
    assert "8.8.8.8" in values
    assert not any(":" in v for v in values)
