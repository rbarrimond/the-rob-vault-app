"""Backward-compatible manifest cache facade built on the new platform services."""

from __future__ import annotations

import logging
import os
import threading
from typing import Optional

from constants import (BUNGIE_API_BASE, DEFAULT_HEADERS, REQUEST_TIMEOUT,
                       STORAGE_CONNECTION_STRING)
from .blob_store import ManifestBlobStore
from .query_service import ManifestSQLiteQueryService


class ManifestCache:
    """Thread-safe singleton facade for blob-backed, SQLite-native manifest access."""

    _instance = None
    _instance_lock = threading.RLock()

    @classmethod
    def instance(cls, *args, **kwargs) -> "ManifestCache":
        """Get the shared manifest cache instance."""
        if cls._instance is None:
            with cls._instance_lock:
                if cls._instance is None:
                    cls._instance = cls(*args, **kwargs)
                    cls._instance.ensure_manifest()
                    cls._instance.prewarm_small_tables()
        return cls._instance

    def __init__(
        self,
        api_base: str = BUNGIE_API_BASE,
        headers: Optional[dict] = None,
        timeout: int = REQUEST_TIMEOUT,
        storage_path: str | None = None,
        storage_connection_string: str | None = STORAGE_CONNECTION_STRING,
    ) -> None:
        self.api_base = api_base
        self.headers = headers or DEFAULT_HEADERS
        self.timeout = timeout
        self.storage_path = storage_path or "/tmp/manifest.content"
        self.storage_connection_string = storage_connection_string or ""
        self.version: str | None = None
        self._lock = threading.RLock()
        self._query_service: ManifestSQLiteQueryService | None = None
        self._blob_store = ManifestBlobStore(
            storage_connection_string=self.storage_connection_string,
            api_base=self.api_base,
            headers=self.headers,
            timeout=self.timeout,
        )

    def __del__(self) -> None:
        self.close()

    def _reinitialize_query_service(self) -> None:
        """Recreate the internal SQLite query service after the manifest file changes."""
        if self._query_service is not None:
            self._query_service.close()
        self._query_service = ManifestSQLiteQueryService(self.storage_path)

    def ensure_manifest(self) -> bool:
        """Ensure the current Bungie manifest version is available locally and ready to query."""
        with self._lock:
            manifest_index = self._blob_store.get_manifest_index()
            if not manifest_index:
                return False

            manifest_version = manifest_index["version"]
            sqlite_path = manifest_index["sqlite_path"]
            if (
                self._query_service is not None
                and self.version == manifest_version
                and os.path.exists(self.storage_path)
            ):
                return True

            hydrated = self._blob_store.hydrate_manifest_to_path(
                manifest_version,
                self.storage_path,
            )
            if not hydrated:
                hydrated = self._blob_store.download_and_persist_manifest(
                    manifest_version,
                    sqlite_path,
                    self.storage_path,
                )
            if not hydrated:
                logging.error("Failed to hydrate manifest version %s.", manifest_version)
                return False

            self.version = manifest_version
            self._reinitialize_query_service()
            return True

    def _get_query_service(self) -> ManifestSQLiteQueryService:
        """Return the initialized query service, ensuring the manifest is ready first."""
        if self._query_service is None and not self.ensure_manifest():
            raise RuntimeError("Manifest is not available for querying.")
        assert self._query_service is not None
        return self._query_service

    def _connect(self):
        """Compatibility helper returning the underlying SQLite connection."""
        return self._get_query_service().connect()

    def prewarm_small_tables(self) -> None:
        """Preload small definition tables into memory for faster lookups."""
        self._get_query_service().prewarm_small_tables()

    def get_definitions_batch(
        self,
        definition_type: str,
        item_hashes: list[int | str],
    ) -> dict[str, dict]:
        """Batch resolve hashes for a manifest definition table."""
        return self._get_query_service().get_definitions_batch(definition_type, item_hashes)

    def resolve_exact(self, item_hash: int | str, definition_type: str) -> dict | None:
        """Resolve a single hash against a specific manifest definition table."""
        return self._get_query_service().resolve_exact(item_hash, definition_type)

    def resolve_many(self, hashes: list[int | str], definition_type: str) -> dict[str, dict]:
        """Resolve many hashes against a specific manifest definition table."""
        return self._get_query_service().resolve_many(hashes, definition_type)

    def get_all_definitions(self, definition_type: str) -> dict[str, dict]:
        """Return all definitions for the specified table."""
        return self._get_query_service().get_all_definitions(definition_type)

    def get_definitions(
        self,
        definition_type: str,
        item_hash: str | int | None = None,
    ) -> dict | None:
        """Compatibility method retained for existing callers."""
        return self._get_query_service().get_definitions(definition_type, item_hash=item_hash)

    def resolve_manifest_hash(self, item_hash: int | str, definition_types: Optional[list[str]] = None):
        """Resolve a hash across one or more manifest definition tables."""
        return self._get_query_service().resolve_manifest_hash(item_hash, definition_types)

    def search_definitions_by_name(
        self,
        definition_type: str,
        query_text: str,
        *,
        limit: int = 25,
    ):
        """Search a manifest definition table by display name."""
        query_service = self._get_query_service()
        return query_service.search_definitions_by_name(
            definition_type,
            query_text,
            limit=limit,
        )

    def close(self) -> None:
        """Close the query service and delete the hydrated local manifest copy."""
        with self._lock:
            if self._query_service is not None:
                self._query_service.close()
                self._query_service = None
            if os.path.exists(self.storage_path):
                try:
                    os.remove(self.storage_path)
                except OSError as exc:
                    logging.warning("Failed to delete manifest DB file: %s", exc)
