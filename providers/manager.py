"""
providers/manager.py

Provider registry and selection logic.

This module is the single place that knows about every provider class.
To add a new provider in the future:

    1. Create providers/<new_provider>.py implementing BaseProvider,
       with a SUPPORTED_TYPES class attribute.
    2. Add a matching ProviderConfig field to config.AppConfig.
    3. Add one line to _PROVIDER_SPECS below.

No other file needs to change, and no if/else chains are needed to decide
which providers run for a given IOC type — that decision is made purely
from each provider's own SUPPORTED_TYPES declaration.
"""

from __future__ import annotations

from config import REQUEST_TIMEOUT, AppConfig
from detector import IOCType
from providers import BaseProvider
from providers.abuseipdb import AbuseIPDBProvider
from providers.malwarebazaar import MalwareBazaarProvider
from providers.otx import OTXProvider
from providers.threatfox import ThreatFoxProvider
from providers.urlhaus import URLhausProvider
from providers.virustotal import VirusTotalProvider

# Each entry maps the AppConfig field name holding that provider's
# ProviderConfig to the provider class that consumes it.
_PROVIDER_SPECS: list[tuple[str, type[BaseProvider]]] = [
    ("virustotal", VirusTotalProvider),
    ("otx", OTXProvider),
    ("threatfox", ThreatFoxProvider),
    ("abuseipdb", AbuseIPDBProvider),
    ("urlhaus", URLhausProvider),
    ("malwarebazaar", MalwareBazaarProvider),
]


def build_all_providers(config: AppConfig) -> list[BaseProvider]:
    """Instantiate every registered provider, regardless of IOC type."""
    providers: list[BaseProvider] = []
    for field_name, provider_cls in _PROVIDER_SPECS:
        provider_cfg = getattr(config, field_name)
        # A provider can opt into its own timeout (see providers/otx.py,
        # which needs longer than the project default) via a
        # DEFAULT_TIMEOUT class attribute; otherwise it gets the global
        # REQUEST_TIMEOUT. No per-provider special-casing needed here.
        timeout = getattr(provider_cls, "DEFAULT_TIMEOUT", REQUEST_TIMEOUT)
        providers.append(provider_cls(provider_cfg.api_key, timeout=timeout))
    return providers


def get_providers_for_type(ioc_type: IOCType, config: AppConfig) -> list[BaseProvider]:
    """
    Return only the providers whose SUPPORTED_TYPES includes the given
    IOC type. Providers that don't support this IOC type are never
    instantiated for the scan and never appear in the results.
    """
    return [
        provider
        for provider in build_all_providers(config)
        if ioc_type in provider.SUPPORTED_TYPES
    ]
