"""Backward-compatible manifest cache facade built on the new platform services."""

from __future__ import annotations

import logging
import threading
from typing import Optional

from VaultSentinelPlatform.config import (
    BUNGIE_API_BASE,
    DEFAULT_HEADERS,
    REQUEST_TIMEOUT,
    STORAGE_CONNECTION_STRING,
)
from VaultSentinelPlatform.exceptions import DependencyUnavailableError
from .blob_store import ManifestBlobStore
from .query_service import ManifestSQLiteQueryService


class ManifestCache:
    """Thread-safe singleton facade for memory-backed, blob-rehydrated manifest access."""

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
        self.storage_path = storage_path
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
        if self.storage_path is not None:
            logging.debug(
                "Ignoring deprecated storage_path %s; manifest now stays in memory.",
                self.storage_path,
            )

    def __del__(self) -> None:
        self.close()

    def _reinitialize_query_service(self, manifest_bytes: bytes) -> None:
        """Recreate the internal SQLite query service from the current manifest bytes."""
        if self._query_service is not None:
            self._query_service.close()
        self._query_service = ManifestSQLiteQueryService(manifest_bytes)

    def _load_manifest_bytes(self, manifest_version: str, sqlite_path: str) -> bytes | None:
        """Load the current manifest bytes from Blob first, then Bungie if needed."""
        try:
            cached_payload = self._blob_store.load_manifest_bytes(manifest_version)
        except DependencyUnavailableError as exc:
            logging.warning(
                "Blob manifest rehydration unavailable for version %s; falling back to Bungie download: %s",
                manifest_version,
                exc,
                exc_info=True,
            )
            cached_payload = None
        if cached_payload is not None:
            logging.info("Rehydrated manifest version %s from Blob cache.", manifest_version)
            return cached_payload

        logging.info(
            "Manifest version %s missing from Blob cache; downloading from Bungie.",
            manifest_version,
        )
        downloaded_payload = self._blob_store.download_manifest_bytes(sqlite_path)
        if downloaded_payload is None:
            return None
        try:
            self._blob_store.save_manifest_bytes(manifest_version, downloaded_payload)
        except DependencyUnavailableError as exc:
            logging.warning(
                "Manifest version %s downloaded successfully but could not be cached to Blob: %s",
                manifest_version,
                exc,
                exc_info=True,
            )
        return downloaded_payload

    def ensure_manifest(self) -> bool:
        """Ensure the current Bungie manifest version is loaded in memory and ready to query."""
        with self._lock:
            manifest_index = self._blob_store.get_manifest_index()
            if not manifest_index:
                return False

            manifest_version = str(manifest_index["version"])
            sqlite_path = manifest_index["sqlite_path"]
            if self._query_service is not None and self.version == manifest_version:
                return True

            manifest_bytes = self._load_manifest_bytes(manifest_version, sqlite_path)
            if manifest_bytes is None:
                logging.error("Failed to load manifest version %s.", manifest_version)
                return False

            try:
                self._reinitialize_query_service(manifest_bytes)
            except DependencyUnavailableError as exc:
                logging.error(
                    "Failed to initialize manifest version %s in memory: %s",
                    manifest_version,
                    exc,
                    exc_info=True,
                )
                return False

            self.version = manifest_version
            return True

    def _get_query_service(self) -> ManifestSQLiteQueryService:
        """Return the initialized query service, ensuring the manifest is ready first."""
        if self._query_service is None and not self.ensure_manifest():
            raise DependencyUnavailableError(
                "Manifest is not available for querying.",
                details={"source": "memory", "manifest_version": self.version},
            )
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
        """Close the in-memory query service and reset the cached manifest version."""
        with self._lock:
            if self._query_service is not None:
                self._query_service.close()
                self._query_service = None
            self.version = None
