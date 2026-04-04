"""Blob-backed persistence for Bungie's native SQLite manifest."""

from __future__ import annotations

import logging
import os
import tempfile
import zipfile
from typing import Callable, Optional

import requests

from constants import (BLOB_CONTAINER, BUNGIE_API_BASE, DEFAULT_HEADERS,
                       REQUEST_TIMEOUT)
from helpers import load_blob, retry_request, save_blob


class ManifestBlobStore:
    """Persist and hydrate Bungie's native `.content` manifest as a versioned blob."""

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
        try:
            response = retry_request(
                requests.get,
                f"{self.api_base}/Destiny2/Manifest/",
                headers=self.headers,
                timeout=self.timeout,
            )
        except (RuntimeError, requests.RequestException, ValueError) as exc:
            logging.error("Failed to fetch manifest index: %s", exc)
            return None

        if not response.ok:
            logging.error("Manifest index fetch failed: %d", response.status_code)
            return None

        payload = response.json().get("Response", {})
        version = payload.get("version")
        sqlite_path = (payload.get("mobileWorldContentPaths") or {}).get("en")
        if not version or not sqlite_path:
            logging.error("Manifest index missing version or SQLite path.")
            return None
        return {"version": version, "sqlite_path": sqlite_path}

    def load_manifest_bytes(self, version: str) -> bytes | None:
        """Load a versioned manifest blob if storage is configured."""
        if not self.storage_connection_string:
            logging.debug(
                "Storage connection string not configured; "
                "skipping manifest blob load."
            )
            return None
        return self._load_blob_func(
            self.storage_connection_string,
            self.container_name,
            self.blob_name_for_version(version),
        )

    def save_manifest_bytes(self, version: str, payload: bytes) -> bool:
        """Persist raw SQLite bytes for the specified manifest version."""
        if not self.storage_connection_string:
            logging.info(
                "Storage connection string not configured; "
                "skipping manifest blob save."
            )
            return False
        self._save_blob_func(
            self.storage_connection_string,
            self.container_name,
            self.blob_name_for_version(version),
            payload,
        )
        logging.info("Saved manifest SQLite blob for version %s.", version)
        return True

    def hydrate_manifest_to_path(self, version: str, local_path: str) -> bool:
        """Hydrate the specified versioned manifest blob to a readable local SQLite file."""
        payload = self.load_manifest_bytes(version)
        if payload is None:
            return False
        os.makedirs(os.path.dirname(local_path) or ".", exist_ok=True)
        with open(local_path, "wb") as handle:
            handle.write(payload)
        logging.info("Hydrated manifest version %s to %s.", version, local_path)
        return True

    def download_manifest_bytes(self, sqlite_path: str) -> bytes | None:
        """Download and extract the raw `.content` SQLite bytes from Bungie."""
        download_url = (
            sqlite_path
            if sqlite_path.startswith("http")
            else f"https://www.bungie.net{sqlite_path}"
        )
        try:
            response = retry_request(requests.get, download_url, timeout=self.timeout)
        except (RuntimeError, requests.RequestException, ValueError) as exc:
            logging.error("Manifest ZIP download failed: %s", exc)
            return None

        if not response.ok:
            logging.error("Manifest ZIP download failed: %d", response.status_code)
            return None

        zip_path: str | None = None
        try:
            with tempfile.NamedTemporaryFile(delete=False, mode="wb") as temp_file:
                temp_file.write(response.content)
                zip_path = temp_file.name
            with zipfile.ZipFile(zip_path, "r") as archive:
                manifest_members = [
                    info
                    for info in archive.infolist()
                    if info.filename.endswith(".content")
                ]
                if not manifest_members:
                    logging.error("No .content file found in manifest ZIP.")
                    return None
                manifest_info = max(manifest_members, key=lambda info: info.file_size)
                return archive.read(manifest_info.filename)
        except (OSError, zipfile.BadZipFile) as exc:
            logging.error("Failed to extract manifest ZIP: %s", exc)
            return None
        finally:
            if zip_path and os.path.exists(zip_path):
                os.remove(zip_path)

    def download_and_persist_manifest(
        self,
        version: str,
        sqlite_path: str,
        local_path: str,
    ) -> bool:
        """Download the manifest from Bungie and persist it locally and in blob storage."""
        payload = self.download_manifest_bytes(sqlite_path)
        if payload is None:
            return False
        os.makedirs(os.path.dirname(local_path) or ".", exist_ok=True)
        with open(local_path, "wb") as handle:
            handle.write(payload)
        self.save_manifest_bytes(version, payload)
        logging.info("Downloaded and hydrated manifest version %s.", version)
        return True
