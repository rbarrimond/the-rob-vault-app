# pylint: disable=broad-exception-caught, line-too-long
"""
ManifestCache module for Destiny 2 manifest management.
Encapsulates manifest data loading, saving, and lookup logic.
"""
import json
import logging
import os
import sqlite3
import tempfile
import threading
import zipfile
import ctypes

import requests

from helpers import normalize_item_hash, retry_request
from constants import BUNGIE_REQUIRED_DEFS, BUNGIE_API_BASE, REQUEST_TIMEOUT, DEFAULT_HEADERS


class ManifestCache:
    """
    Singleton for Destiny 2 manifest SQLite DB in ephemeral storage.
    Use ManifestCache.instance() to get the shared instance.
    Call close() when shutting down to release resources and delete the DB file.
    """
    _instance = None

    @classmethod
    def instance(cls, *args, **kwargs) -> "ManifestCache":
        """
        Get the shared instance of the ManifestCache singleton.
        """
        if cls._instance is None:
            cls._instance = cls(*args, **kwargs)
        return cls._instance

    def __del__(self):
        self.close()


    def __init__(
        self,
        api_base: str = BUNGIE_API_BASE,
        headers: dict = None,
        timeout: int = REQUEST_TIMEOUT,
        storage_path: str = None
    ):
        self.api_base = api_base
        self.headers = headers or DEFAULT_HEADERS
        self.timeout = timeout
        self.storage_path = storage_path or "/tmp/manifest.content"
        self.version = None
        self._lock = threading.RLock()
        self._conn = None

    def ensure_manifest(self) -> bool:
        """
        Ensure the Destiny 2 manifest SQLite database is present and up-to-date.
        Downloads and extracts the manifest if missing or outdated.
        Returns:
            bool: True if manifest is ready, False otherwise.
        """
        with self._lock:
            index_resp = retry_request(
                requests.get,
                f"{self.api_base}/Destiny2/Manifest/",
                headers=self.headers,
                timeout=self.timeout
            )
            if not index_resp.ok:
                logging.error("Manifest index fetch failed: %d",
                              index_resp.status_code)
                return False
            index_data = index_resp.json().get("Response", {})
            manifest_version = index_data.get("version")
            sqlite_path = index_data.get(
                "mobileWorldContentPaths", {}).get("en")
            if not sqlite_path:
                logging.error("Manifest index missing SQLite path.")
                return False
            # If manifest exists and version matches, skip download
            if os.path.exists(self.storage_path) and self.version == manifest_version:
                return True
            # Download ZIP
            url = f"https://www.bungie.net{sqlite_path}"
            resp = retry_request(requests.get, url, timeout=self.timeout)
            if not resp.ok:
                logging.error("Manifest ZIP download failed: %d",
                              resp.status_code)
                return False
            with tempfile.NamedTemporaryFile(delete=False, mode="wb") as tmp_file:
                tmp_file.write(resp.content)
                zip_path = tmp_file.name
            try:
                with zipfile.ZipFile(zip_path, 'r') as zf:
                    manifest_files = [info for info in zf.infolist(
                    ) if info.filename.endswith('.content')]
                    if not manifest_files:
                        logging.error(
                            "No .content file found in manifest ZIP.")
                        return False
                    manifest_info = max(
                        manifest_files, key=lambda info: info.file_size)
                    with open(self.storage_path, 'wb') as sqlite_file:
                        with zf.open(manifest_info.filename, 'r') as src:
                            sqlite_file.write(src.read())
                self.version = manifest_version
                return True
            finally:
                os.remove(zip_path)

    def _connect(self) -> sqlite3.Connection:
        """
        Open a thread-safe SQLite connection to the manifest database (private).
        Returns:
            sqlite3.Connection: SQLite connection object.
        Raises:
            FileNotFoundError: If manifest DB file is missing.
        """
        with self._lock:
            if self._conn:
                return self._conn
            if not os.path.exists(self.storage_path):
                raise FileNotFoundError(
                    f"Manifest DB not found at {self.storage_path}")
            self._conn = sqlite3.connect(self.storage_path)
            return self._conn

    def get_definitions(self, definition_type: str, item_hash: str | int = None) -> dict | None:
        """
        Retrieve manifest definitions for a given type/table.
        If item_hash is provided, returns a single definition dict or None.
        If item_hash is None, returns all definitions as a dict.
        Args:
            definition_type (str): Manifest table name (e.g., DestinyInventoryItemDefinition).
            item_hash (str|int, optional): Destiny item hash to look up.
        Returns:
            dict: Mapping of item hash (str) to manifest definition dict, or single definition dict if item_hash is provided.
        """
        with self._lock:
            conn = self._connect()
            cursor = conn.cursor()
            if item_hash is not None:
                norm_hash = normalize_item_hash(item_hash)  # unsigned u32
                # two's complement signed form
                signed_hash = ctypes.c_int32(int(norm_hash)).value
                try:
                    cursor.execute(
                        f"SELECT json FROM {definition_type} WHERE id IN (?, ?) LIMIT 1",
                        (signed_hash, norm_hash),
                    )
                    row = cursor.fetchone()
                    if row:
                        return json.loads(row[0])
                except Exception as e:
                    logging.error(
                        "Manifest lookup failed for %s (u32=%s, i32=%s): %s",
                        definition_type, norm_hash, signed_hash, e,
                    )
                return None
            else:
                defs = {}
                try:
                    cursor.execute(f"SELECT id, json FROM {definition_type}")
                    for row in cursor.fetchall():
                        try:
                            # normalize to unsigned u32 key
                            uid = int(row[0]) & 0xFFFFFFFF
                            defs[str(uid)] = json.loads(row[1])
                        except Exception:
                            continue
                except Exception as e:
                    logging.error(
                        "Manifest get_definitions failed for %s: %s", definition_type, e)
                return defs

    def resolve_manifest_hash(self, item_hash: int | str, definition_types: list[str] = None) -> tuple[dict | None, str | None]:
        """
        Attempt to resolve a hash against multiple manifest definition types.

        Args:
            item_hash (str or int): The item hash to resolve.
            definition_types (list, optional): List of definition types to search. If None, all loaded types are used.

        Returns:
            tuple: (definition object, definition type) if found, otherwise (None, None).
        """
        logging.debug("Attempting to resolve manifest hash: %s across types: %s",
                      item_hash, definition_types if definition_types else BUNGIE_REQUIRED_DEFS)
        if not definition_types:
            definition_types = BUNGIE_REQUIRED_DEFS
        item_hash = str(item_hash)
        for def_type in definition_types:
            defs = self.get_definitions(def_type, item_hash)
            if defs:
                logging.info("Manifest hash %s found in %s.", item_hash, def_type)
                return defs, def_type
            else:
                logging.debug("Manifest hash %s not found in %s.", item_hash, def_type)
        return None, None

    def close(self) -> None:
        """
        Close the SQLite connection and delete the manifest DB file.
        Call this explicitly when shutting down the app to ensure cleanup.
        """
        with self._lock:
            if self._conn:
                self._conn.close()
                self._conn = None
            if os.path.exists(self.storage_path):
                try:
                    os.remove(self.storage_path)
                except Exception as e:
                    logging.warning("Failed to delete manifest DB file: %s", e)
