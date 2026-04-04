"""Unit tests for the manifest blob store."""

# pylint: disable=import-error,protected-access

from __future__ import annotations

import io
import zipfile

import pytest
from azure.core.exceptions import AzureError

import VaultSentinelPlatform.manifest.blob_store as blob_store_module
from VaultSentinelPlatform.exceptions import DependencyUnavailableError
from VaultSentinelPlatform.manifest.blob_store import ManifestBlobStore


def test_blob_store_uses_versioned_manifest_names():
    """Manifest blobs should be versioned so the native SQLite payload can be cached safely."""
    store = ManifestBlobStore(storage_connection_string="UseDevelopmentStorage=true")
    assert (
        store.blob_name_for_version("2026.04.03.1200-1")
        == "manifest/2026.04.03.1200-1/world.content"
    )


def test_blob_store_round_trips_sqlite_bytes():
    """The blob store should persist and rehydrate the raw SQLite bytes unchanged."""
    payload = b"SQLite format 3\x00manifest-bytes"
    saved = {}

    def _fake_save(connection_string, container_name, blob_name, data, content_type=None):
        saved["args"] = (connection_string, container_name, blob_name, data, content_type)

    def _fake_load(connection_string, container_name, blob_name):
        assert (connection_string, container_name, blob_name) == saved["args"][:3]
        return payload

    store = ManifestBlobStore(
        storage_connection_string="UseDevelopmentStorage=true",
        save_blob_func=_fake_save,
        load_blob_func=_fake_load,
    )

    store.save_manifest_bytes("2026.04.03.1200-1", payload)
    assert store.load_manifest_bytes("2026.04.03.1200-1") == payload


def test_blob_store_download_manifest_extracts_sqlite_bytes_in_memory(monkeypatch):
    """Manifest ZIP extraction should stay in memory and return the native SQLite payload."""
    payload = b"SQLite format 3\x00downloaded-manifest"
    archive_bytes = io.BytesIO()
    with zipfile.ZipFile(archive_bytes, "w") as archive:
        archive.writestr("world_sql_content_1.content", payload)

    class _Response:
        ok = True
        status_code = 200
        content = archive_bytes.getvalue()

    monkeypatch.setattr(
        blob_store_module,
        "retry_request",
        lambda *args, **kwargs: _Response(),
    )

    store = ManifestBlobStore(storage_connection_string="UseDevelopmentStorage=true")
    assert store.download_manifest_bytes("/path/to/world_sql_content_1.zip") == payload


def test_blob_store_wraps_manifest_index_failures_as_dependency_errors(monkeypatch):
    """Bungie manifest-index failures should surface as typed dependency errors with causality."""
    outage = RuntimeError("manifest endpoint timed out")

    def _raise_outage(*args, **kwargs):
        raise outage

    monkeypatch.setattr(blob_store_module, "retry_request", _raise_outage)

    store = ManifestBlobStore(storage_connection_string="UseDevelopmentStorage=true")

    with pytest.raises(DependencyUnavailableError, match="Failed to fetch manifest index") as exc_info:
        store.get_manifest_index()

    assert exc_info.value.__cause__ is outage


def test_blob_store_wraps_zip_download_failures_as_dependency_errors(monkeypatch):
    """Manifest ZIP download/extraction failures should not leak raw runtime or zipfile exceptions."""
    outage = AzureError("blob gateway unavailable")

    def _raise_outage(*args, **kwargs):
        raise outage

    monkeypatch.setattr(blob_store_module, "retry_request", _raise_outage)

    store = ManifestBlobStore(storage_connection_string="UseDevelopmentStorage=true")

    with pytest.raises(DependencyUnavailableError, match="Manifest ZIP download failed") as exc_info:
        store.download_manifest_bytes("/path/to/world_sql_content_1.zip")

    assert exc_info.value.__cause__ is outage
