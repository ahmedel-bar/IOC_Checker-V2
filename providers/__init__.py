"""
providers package

Every provider module (virustotal.py, otx.py, threatfox.py, abuseipdb.py,
urlhaus.py, malwarebazaar.py) implements the
BaseProvider interface below, exposing:

    lookup_ip(ioc: str) -> ProviderResult
    lookup_domain(ioc: str) -> ProviderResult
    lookup_url(ioc: str) -> ProviderResult
    lookup_hash(ioc: str) -> ProviderResult

This guarantees the main application never needs to know which provider
produced a given result.

Each provider also declares a class-level `SUPPORTED_TYPES` set of
`detector.IOCType` values. This is the single source of truth used by
`providers.manager` to decide which providers get queried for a given
IOC type — no hardcoded if/else chains are needed anywhere else in the
project. Adding a new provider is therefore just:

    1. Create providers/<new_provider>.py implementing BaseProvider.
    2. Add its ProviderConfig to config.py.
    3. Register it in providers/manager.py's _PROVIDER_SPECS list.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from detector import IOCType
from utils import ProviderResult


class BaseProvider(ABC):
    """Abstract base class defining the common provider interface."""

    name: str = "BaseProvider"

    # The set of IOC types this provider knows how to look up. Subclasses
    # must override this. Used by providers.manager for dynamic selection.
    SUPPORTED_TYPES: set[IOCType] = set()

    @abstractmethod
    def lookup_ip(self, ioc: str) -> ProviderResult: ...

    @abstractmethod
    def lookup_domain(self, ioc: str) -> ProviderResult: ...

    @abstractmethod
    def lookup_url(self, ioc: str) -> ProviderResult: ...

    @abstractmethod
    def lookup_hash(self, ioc: str) -> ProviderResult: ...
