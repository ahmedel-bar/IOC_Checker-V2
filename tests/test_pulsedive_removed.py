"""
tests/test_pulsedive_removed.py

Regression guard: Pulsedive was fully removed from the project. This
just confirms it doesn't quietly come back - no provider module, no
registry entry, no config field.
"""

from __future__ import annotations

import importlib

import pytest

from config import load_config
from providers.manager import build_all_providers


def test_pulsedive_module_does_not_exist():
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module("providers.pulsedive")


def test_pulsedive_not_in_config():
    config = load_config()
    names = [p.display_name for p in config.all_providers()]
    assert "Pulsedive" not in names
    assert not hasattr(config, "pulsedive")


def test_pulsedive_not_in_provider_registry():
    config = load_config()
    providers = build_all_providers(config)
    names = [p.name for p in providers]
    assert "Pulsedive" not in names


def test_six_providers_remain():
    config = load_config()
    providers = build_all_providers(config)
    expected = {"VirusTotal", "AlienVault OTX", "ThreatFox", "AbuseIPDB", "URLhaus", "MalwareBazaar"}
    assert {p.name for p in providers} == expected
