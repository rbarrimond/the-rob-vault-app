"""Unit tests for the manifest SQLite query service."""

# pylint: disable=import-error,protected-access

from __future__ import annotations

import json
import sqlite3
from unittest.mock import MagicMock, patch

import pytest

from VaultSentinelPlatform.exceptions import DependencyUnavailableError
from VaultSentinelPlatform.manifest.cache import ManifestCache
from VaultSentinelPlatform.manifest.query_service import ManifestSQLiteQueryService


SAMPLE_ITEM_HASH = 123456
SAMPLE_STAT_HASH = 987654


class _FakeBlobStore:
    def __init__(
        self,
        *,
        manifest_index,
        load_manifest_bytes,
        download_manifest_bytes,
        save_manifest_bytes,
    ) -> None:
        self.get_manifest_index = lambda: manifest_index
        self.load_manifest_bytes = load_manifest_bytes
        self.download_manifest_bytes = download_manifest_bytes
        self.save_manifest_bytes = save_manifest_bytes


def _build_manifest_bytes() -> bytes:
    conn = sqlite3.connect(":memory:")
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
        return conn.serialize()
    finally:
        conn.close()


def test_query_service_resolves_exact_many_and_cross_type():
    """The query service should preserve exact, batched, and cross-type manifest lookups."""
    service = ManifestSQLiteQueryService(_build_manifest_bytes())
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


def test_query_service_supports_name_search():
    """The new semantic query layer should support typed name search within a manifest table."""
    service = ManifestSQLiteQueryService(_build_manifest_bytes())
    try:
        results = service.search_definitions_by_name("DestinyInventoryItemDefinition", "midnight")
        assert len(results) == 1
        assert results[0]["displayProperties"]["name"] == "Midnight Coup"
    finally:
        service.close()


def test_query_service_wraps_lookup_failures_as_dependency_errors() -> None:
    """Runtime SQLite lookup failures should be translated into platform dependency errors."""
    service = ManifestSQLiteQueryService(_build_manifest_bytes())
    fake_cursor = MagicMock()
    fake_cursor.execute.side_effect = sqlite3.Error("malformed manifest table")
    fake_connection = MagicMock()
    fake_connection.cursor.return_value = fake_cursor

    try:
        with patch.object(service, "_connect", return_value=fake_connection):
            with pytest.raises(DependencyUnavailableError, match="Manifest lookup failed") as exc_info:
                service.resolve_exact(SAMPLE_ITEM_HASH, "DestinyInventoryItemDefinition")
    finally:
        service.close()

    assert exc_info.value.__cause__ is not None


def test_query_service_wraps_name_search_failures_as_dependency_errors() -> None:
    """Manifest name search should not leak raw sqlite exceptions to callers."""
    service = ManifestSQLiteQueryService(_build_manifest_bytes())
    fake_cursor = MagicMock()
    fake_cursor.execute.side_effect = sqlite3.Error("sqlite is locked")
    fake_connection = MagicMock()
    fake_connection.cursor.return_value = fake_cursor

    try:
        with patch.object(service, "_connect", return_value=fake_connection):
            with pytest.raises(DependencyUnavailableError, match="Manifest name search failed") as exc_info:
                service.search_definitions_by_name("DestinyInventoryItemDefinition", "midnight")
    finally:
        service.close()

    assert exc_info.value.__cause__ is not None


def test_query_service_raises_business_exception_when_manifest_bytes_missing():
    """Missing in-memory manifest payloads should surface as platform dependency errors."""
    service = ManifestSQLiteQueryService(b"")

    with pytest.raises(DependencyUnavailableError, match="Manifest DB payload is not available"):
        service.connect()


def test_manifest_cache_raises_business_exception_when_manifest_unavailable():
    """Manifest cache availability failures should remain within the platform exception hierarchy."""
    cache = ManifestCache()

    cache.ensure_manifest = lambda: False

    with pytest.raises(DependencyUnavailableError, match="Manifest is not available"):
        cache.prewarm_small_tables()


def test_manifest_cache_prefers_blob_rehydration_before_bungie_download():
    """Cold starts should rehydrate the current manifest from Blob before considering Bungie download."""
    version = "2026.04.03.1200-1"
    payload = _build_manifest_bytes()
    events: list[tuple[str, str]] = []
    cache = ManifestCache()
    fake_blob_store = _FakeBlobStore(
        manifest_index={
            "version": version,
            "sqlite_path": "/manifest/world_sql_content_1.zip",
        },
        load_manifest_bytes=lambda requested_version: (
            events.append(("load", requested_version)) or payload
        ),
        download_manifest_bytes=lambda sqlite_path: (
            events.append(("download", sqlite_path)) or None
        ),
        save_manifest_bytes=lambda requested_version, data: (
            events.append(("save", requested_version)) or True
        ),
    )
    setattr(cache, "_blob_store", fake_blob_store)

    try:
        assert cache.ensure_manifest() is True
        assert cache.resolve_exact(SAMPLE_ITEM_HASH, "DestinyInventoryItemDefinition") is not None
        assert events == [("load", version)]
    finally:
        cache.close()


def test_manifest_cache_downloads_and_persists_when_blob_misses():
    """If the current version is absent from Blob storage, the cache should fetch from Bungie and persist it."""
    version = "2026.04.03.1200-1"
    payload = _build_manifest_bytes()
    events: list[tuple[str, str]] = []
    cache = ManifestCache()

    def _load(requested_version):
        events.append(("load", requested_version))
        return None

    def _download(sqlite_path):
        events.append(("download", sqlite_path))
        return payload

    def _save(requested_version, data):
        assert data == payload
        events.append(("save", requested_version))
        return True

    fake_blob_store = _FakeBlobStore(
        manifest_index={
            "version": version,
            "sqlite_path": "/manifest/world_sql_content_1.zip",
        },
        load_manifest_bytes=_load,
        download_manifest_bytes=_download,
        save_manifest_bytes=_save,
    )
    setattr(cache, "_blob_store", fake_blob_store)

    try:
        assert cache.ensure_manifest() is True
        item_def = cache.resolve_exact(SAMPLE_ITEM_HASH, "DestinyInventoryItemDefinition")
        assert item_def is not None
        assert events == [
            ("load", version),
            ("download", "/manifest/world_sql_content_1.zip"),
            ("save", version),
        ]
    finally:
        cache.close()


def test_manifest_cache_falls_back_when_blob_cache_is_unavailable():
    """A blob cache outage should still allow a Bungie download fallback for manifest availability."""
    version = "2026.04.03.1200-1"
    payload = _build_manifest_bytes()
    events: list[tuple[str, str]] = []
    cache = ManifestCache()

    def _load(requested_version):
        events.append(("load", requested_version))
        raise DependencyUnavailableError("blob cache unavailable")

    def _download(sqlite_path):
        events.append(("download", sqlite_path))
        return payload

    def _save(requested_version, data):
        assert data == payload
        events.append(("save", requested_version))
        return True

    fake_blob_store = _FakeBlobStore(
        manifest_index={
            "version": version,
            "sqlite_path": "/manifest/world_sql_content_1.zip",
        },
        load_manifest_bytes=_load,
        download_manifest_bytes=_download,
        save_manifest_bytes=_save,
    )
    setattr(cache, "_blob_store", fake_blob_store)

    try:
        assert cache.ensure_manifest() is True
        assert cache.resolve_exact(SAMPLE_ITEM_HASH, "DestinyInventoryItemDefinition") is not None
        assert events == [
            ("load", version),
            ("download", "/manifest/world_sql_content_1.zip"),
            ("save", version),
        ]
    finally:
        cache.close()


def test_manifest_cache_uses_downloaded_manifest_when_blob_save_fails():
    """A blob persistence outage should not discard a successfully downloaded manifest payload."""
    version = "2026.04.03.1200-1"
    payload = _build_manifest_bytes()
    events: list[tuple[str, str]] = []
    cache = ManifestCache()

    def _load(requested_version):
        events.append(("load", requested_version))
        return None

    def _download(sqlite_path):
        events.append(("download", sqlite_path))
        return payload

    def _save(requested_version, data):
        assert data == payload
        events.append(("save", requested_version))
        raise DependencyUnavailableError("blob save unavailable")

    fake_blob_store = _FakeBlobStore(
        manifest_index={
            "version": version,
            "sqlite_path": "/manifest/world_sql_content_1.zip",
        },
        load_manifest_bytes=_load,
        download_manifest_bytes=_download,
        save_manifest_bytes=_save,
    )
    setattr(cache, "_blob_store", fake_blob_store)

    try:
        assert cache.ensure_manifest() is True
        assert cache.resolve_exact(SAMPLE_ITEM_HASH, "DestinyInventoryItemDefinition") is not None
        assert events == [
            ("load", version),
            ("download", "/manifest/world_sql_content_1.zip"),
            ("save", version),
        ]
    finally:
        cache.close()
