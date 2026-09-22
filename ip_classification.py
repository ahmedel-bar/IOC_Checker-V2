"""
ip_classification.py

Shared IPv4 internal/external classification.

Used at two points in the pipeline:
    1. Extraction time (artifacts/_scan.py, artifacts/pcap.py) - so a
       private/reserved address is identified the moment it's found,
       before it's ever considered a candidate for threat-intel lookup.
    2. Aggregation (ioc/aggregator.py) - which still needs the flag on
       every aggregated entry for accurate summary statistics (Internal
       vs External counts), even though internal addresses never become
       lookup candidates.

Having one shared function (rather than two separate implementations)
means extraction and aggregation can never disagree about what counts as
"internal".

Uses Python's ipaddress module's built-in classification properties, not
a hardcoded list of private CIDR ranges, so the result stays correct for
every non-publicly-routable category: RFC 1918 private ranges, loopback
(127.0.0.0/8), link-local (169.254.0.0/16), multicast (224.0.0.0/4),
reserved ranges, and unspecified (0.0.0.0).

Note: `IPv4Address.is_global` is intentionally NOT used here on its own -
it actually reports multicast addresses (e.g. 224.0.0.1) as "global",
which is not what we want for "is this a legitimate external lookup
target". Explicitly OR-ing the specific non-public categories avoids
that trap.
"""

from __future__ import annotations

import ipaddress


def is_internal_ipv4(value: str) -> bool:
    """
    True if `value` is not a meaningful public/external IPv4 address for
    threat-intelligence lookup purposes: private (RFC 1918), loopback,
    link-local, multicast, reserved, or unspecified. False (external) for
    ordinary publicly-routable addresses. False for anything that isn't a
    valid IPv4 address at all (callers are expected to have already
    validated the value is a real IPv4 address).
    """
    try:
        address = ipaddress.IPv4Address(value)
    except ValueError:
        return False

    return (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )
