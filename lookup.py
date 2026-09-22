"""
lookup.py

Shared provider-lookup primitives used by both the direct single-IOC
pipeline (ioc_checker.py) and the artifact-analysis pipeline
(artifact_pipeline.py), so the safe-invocation wrapper and the
IOC-type -> provider-method mapping exist in exactly one place.
"""

from __future__ import annotations

import logging

from detector import IOCType
from providers import BaseProvider
from utils import ProviderResult, Verdict

logger = logging.getLogger("ioc_checker")

# Maps each supported IOC type to the provider method name that handles it.
# Every provider implements all four methods (see providers.BaseProvider),
# so this mapping is provider-agnostic.
LOOKUP_METHOD: dict[IOCType, str] = {
    IOCType.IPV4: "lookup_ip",
    IOCType.DOMAIN: "lookup_domain",
    IOCType.URL: "lookup_url",
    IOCType.MD5: "lookup_hash",
    IOCType.SHA1: "lookup_hash",
    IOCType.SHA256: "lookup_hash",
}


def query_provider(provider: BaseProvider, method_name: str, ioc: str) -> ProviderResult:
    """Safely invoke a provider's lookup method, guaranteeing no exception escapes."""
    try:
        method = getattr(provider, method_name)
        return method(ioc)
    except Exception as exc:  # noqa: BLE001 - provider errors must never crash the CLI
        logger.exception("Unhandled error in provider %s", provider.name)
        return ProviderResult(
            provider=provider.name,
            verdict=Verdict.ERROR,
            details=f"Unhandled error: {exc}",
        )
