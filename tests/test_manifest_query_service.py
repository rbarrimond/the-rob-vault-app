"""Unit tests for the manifest SQLite query service."""

# pylint: disable=import-error

import json
import sqlite3

import pytest

from VaultSentinelPlatform.exceptions import DependencyUnavailableError
from VaultSentinelPlatform.manifest.cache import ManifestCache
from VaultSentinelPlatform.manifest.query_service import ManifestSQLiteQueryService


SAMPLE_ITEM_HASH = 123456
SAMPLE_STAT_HASH = 987654


def _build_manifest_db(db_path):
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            "CREATE TABLE DestinyInventoryItemDefinition "
            "(id INTEGER PRIMARY KEY, json TEXT NOT NULL)"
        )
        conn.execute(
            "CREATE TABLE DestinyStatDefinition "
            "(id INTEGER PRIMARY KEY, json TEXT NOT NULL)"
        )
        conn.execute(
            "INSERT INTO DestinyInventoryItemDefinition (id, json) VALUES (?, ?)",
            (
                SAMPLE_ITEM_HASH,
                json.dumps({
                    "displayProperties": {
                        "name": "Midnight Coup",
                        "description": "Classic hand cannon",
                    },
                    "itemTypeDisplayName": "Hand Cannon",
                    "inventory": {"tierTypeName": "Legendary"},
                }),
            ),
        )
        conn.execute(
            "INSERT INTO DestinyStatDefinition (id, json) VALUES (?, ?)",
            (
                SAMPLE_STAT_HASH,
                json.dumps({
                    "displayProperties": {
                        "name": "Discipline",
                        "description": "Reduces grenade cooldown",
                    }
                }),
            ),
        )
        conn.commit()
    finally:
        conn.close()


def test_query_service_resolves_exact_many_and_cross_type(tmp_path):
    """The query service should preserve exact, batched, and cross-type manifest lookups."""
    db_path = tmp_path / "manifest.content"
    _build_manifest_db(db_path)

    service = ManifestSQLiteQueryService(str(db_path))
    try:
        item_def = service.resolve_exact(SAMPLE_ITEM_HASH, "DestinyInventoryItemDefinition")
        assert item_def is not None
        assert item_def["displayProperties"]["name"] == "Midnight Coup"

        many_defs = service.resolve_many(
            [SAMPLE_ITEM_HASH, 999999],
            "DestinyInventoryItemDefinition",
        )
        assert str(SAMPLE_ITEM_HASH) in many_defs
        assert many_defs[str(SAMPLE_ITEM_HASH)]["itemTypeDisplayName"] == "Hand Cannon"
        assert "999999" not in many_defs

        resolved_def, resolved_type = service.resolve_manifest_hash(
            SAMPLE_STAT_HASH,
            ["DestinyInventoryItemDefinition", "DestinyStatDefinition"],
        )
        assert resolved_type == "DestinyStatDefinition"
        assert resolved_def["displayProperties"]["name"] == "Discipline"
    finally:
        service.close()


def test_query_service_supports_name_search(tmp_path):
    """The new semantic query layer should support typed name search within a manifest table."""
    db_path = tmp_path / "manifest.content"
    _build_manifest_db(db_path)

    service = ManifestSQLiteQueryService(str(db_path))
    try:
        results = service.search_definitions_by_name("DestinyInventoryItemDefinition", "midnight")
        assert len(results) == 1
        assert results[0]["displayProperties"]["name"] == "Midnight Coup"
    finally:
        service.close()


def test_query_service_raises_business_exception_when_manifest_db_missing(tmp_path):
    """Missing manifest files should surface as platform dependency errors."""
    missing_path = tmp_path / "missing.content"
    service = ManifestSQLiteQueryService(str(missing_path))

    with pytest.raises(DependencyUnavailableError, match="Manifest DB not found"):
        service.connect()


def test_manifest_cache_raises_business_exception_when_manifest_unavailable(tmp_path):
    """Manifest cache availability failures should remain within the platform exception hierarchy."""
    cache = ManifestCache(storage_path=str(tmp_path / "manifest.content"))

    cache.ensure_manifest = lambda: False

    with pytest.raises(DependencyUnavailableError, match="Manifest is not available"):
        cache.prewarm_small_tables()
