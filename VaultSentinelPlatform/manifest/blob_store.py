"""Blob-backed persistence for Bungie's native SQLite manifest."""

from __future__ import annotations

import io
import logging
import zipfile
from typing import Callable, Never, Optional

import requests
from azure.core.exceptions import AzureError

from VaultSentinelPlatform.common.helpers import load_blob, retry_request, save_blob
from VaultSentinelPlatform.config import (
    BLOB_CONTAINER,
    BUNGIE_API_BASE,
    DEFAULT_HEADERS,
    REQUEST_TIMEOUT,
)
from VaultSentinelPlatform.exceptions import DependencyUnavailableError


class ManifestBlobStore:
    """Persist and rehydrate Bungie's native `.content` manifest as a versioned blob."""

    @staticmethod
    def _raise_dependency_unavailable(
        message: str,
        *,
        cause: Exception,
        **details,
    ) -> Never:
        """Translate low-level manifest storage/network failures into platform dependency errors."""
        raise DependencyUnavailableError(message, details=details) from cause

    def __init__(
        self,
        storage_connection_string: str | None,
        container_name: str = BLOB_CONTAINER,
        api_base: str = BUNGIE_API_BASE,
        headers: Optional[dict] = None,
        timeout: int = REQUEST_TIMEOUT,
        save_blob_func: Callable[..., None] = save_blob,
        load_blob_func: Callable[..., bytes | None] = load_blob,
    ) -> None:
        self.storage_connection_string = storage_connection_string or ""
        self.container_name = container_name
        self.api_base = api_base
        self.headers = headers or DEFAULT_HEADERS
        self.timeout = timeout
        self._save_blob_func = save_blob_func
        self._load_blob_func = load_blob_func

    @staticmethod
    def blob_name_for_version(version: str) -> str:
        """Return the versioned blob name for a Bungie manifest SQLite payload."""
        return f"manifest/{version}/world.content"

    def get_manifest_index(self) -> dict[str, str] | None:
        """Fetch the current Bungie manifest version and SQLite path."""
        manifest_url = f"{self.api_base}/Destiny2/Manifest/"
        try:
            response = retry_request(
                requests.get,
                manifest_url,
                headers=self.headers,
                timeout=self.timeout,
            )
        except (RuntimeError, requests.RequestException, ValueError, AzureError) as exc:
            logging.error("Failed to fetch manifest index: %s", exc, exc_info=True)
            self._raise_dependency_unavailable(
                "Failed to fetch manifest index.",
                cause=exc,
                dependency="bungie_manifest_index",
                url=manifest_url,
            )

        if not response.ok:
            logging.error("Manifest index fetch failed: %d", response.status_code)
            raise DependencyUnavailableError(
                "Failed to fetch manifest index.",
                details={
                    "dependency": "bungie_manifest_index",
                    "status_code": response.status_code,
                    "url": manifest_url,
                },
            )

        try:
            payload = response.json().get("Response", {})
            version = payload.get("version")
            sqlite_path = (payload.get("mobileWorldContentPaths") or {}).get("en")
        except (AttributeError, TypeError, ValueError) as exc:
            logging.error("Manifest index payload could not be parsed: %s", exc, exc_info=True)
            self._raise_dependency_unavailable(
                "Failed to parse manifest index response.",
                cause=exc,
                dependency="bungie_manifest_index",
                url=manifest_url,
            )

        if not version or not sqlite_path:
            logging.error("Manifest index missing version or SQLite path.")
            raise DependencyUnavailableError(
                "Manifest index missing version or SQLite path.",
                details={"dependency": "bungie_manifest_index", "url": manifest_url},
            )
        return {"version": version, "sqlite_path": sqlite_path}

    def load_manifest_bytes(self, version: str) -> bytes | None:
        """Load a versioned manifest blob if storage is configured."""
        if not self.storage_connection_string:
            logging.debug(
                "Storage connection string not configured; "
                "skipping manifest blob load."
            )
            return None
        try:
            return self._load_blob_func(
                self.storage_connection_string,
                self.container_name,
                self.blob_name_for_version(version),
            )
        except (DependencyUnavailableError, RuntimeError, ValueError, TypeError, OSError) as exc:
            logging.error("Failed to load manifest blob for version %s: %s", version, exc, exc_info=True)
            self._raise_dependency_unavailable(
                "Failed to load manifest blob from storage.",
                cause=exc,
                dependency="blob_storage",
                version=version,
                blob_name=self.blob_name_for_version(version),
            )

    def save_manifest_bytes(self, version: str, payload: bytes) -> bool:
        """Persist raw SQLite bytes for the specified manifest version."""
        if not self.storage_connection_string:
            logging.info(
                "Storage connection string not configured; "
                "skipping manifest blob save."
            )
            return False
        try:
            self._save_blob_func(
                self.storage_connection_string,
                self.container_name,
                self.blob_name_for_version(version),
                payload,
            )
        except (DependencyUnavailableError, RuntimeError, ValueError, TypeError, OSError) as exc:
            logging.error("Failed to save manifest blob for version %s: %s", version, exc, exc_info=True)
            self._raise_dependency_unavailable(
                "Failed to save manifest blob to storage.",
                cause=exc,
                dependency="blob_storage",
                version=version,
                blob_name=self.blob_name_for_version(version),
            )
        logging.info("Saved manifest SQLite blob for version %s.", version)
        return True

    def download_manifest_bytes(self, sqlite_path: str) -> bytes | None:
        """Download and extract the raw `.content` SQLite bytes from Bungie in memory."""
        download_url = (
            sqlite_path
            if sqlite_path.startswith("http")
            else f"https://www.bungie.net{sqlite_path}"
        )
        try:
            response = retry_request(requests.get, download_url, timeout=self.timeout)
        except (RuntimeError, requests.RequestException, ValueError, AzureError) as exc:
            logging.error("Manifest ZIP download failed: %s", exc, exc_info=True)
            self._raise_dependency_unavailable(
                "Manifest ZIP download failed.",
                cause=exc,
                dependency="bungie_manifest_download",
                url=download_url,
            )

        if not response.ok:
            logging.error("Manifest ZIP download failed: %d", response.status_code)
            raise DependencyUnavailableError(
                "Manifest ZIP download failed.",
                details={
                    "dependency": "bungie_manifest_download",
                    "status_code": response.status_code,
                    "url": download_url,
                },
            )

        try:
            with zipfile.ZipFile(io.BytesIO(response.content), "r") as archive:
                manifest_members = [
                    info
                    for info in archive.infolist()
                    if info.filename.endswith(".content")
                ]
                if not manifest_members:
                    logging.error("No .content file found in manifest ZIP.")
                    raise DependencyUnavailableError(
                        "Manifest ZIP did not contain a `.content` payload.",
                        details={"dependency": "bungie_manifest_download", "url": download_url},
                    )
                manifest_info = max(manifest_members, key=lambda info: info.file_size)
                return archive.read(manifest_info.filename)
        except (KeyError, OSError, ValueError, zipfile.BadZipFile) as exc:
            logging.error("Failed to extract manifest ZIP: %s", exc, exc_info=True)
            self._raise_dependency_unavailable(
                "Failed to extract manifest ZIP.",
                cause=exc,
                dependency="bungie_manifest_download",
                url=download_url,
            )

    def download_and_persist_manifest(
        self,
        version: str,
        sqlite_path: str,
    ) -> bytes | None:
        """Download the manifest from Bungie and persist its bytes to Blob storage."""
        payload = self.download_manifest_bytes(sqlite_path)
        if payload is None:
            return None
        self.save_manifest_bytes(version, payload)
        logging.info("Downloaded manifest version %s from Bungie.", version)
        return payload
