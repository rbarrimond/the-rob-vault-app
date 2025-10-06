# pylint: disable=broad-exception-caught, line-too-long
"""
ManifestCache module for Destiny 2 manifest management.

Encapsulates manifest data loading, saving, and lookup logic for Destiny 2 manifest SQLite database.
Provides thread-safe singleton access, manifest download/update, and fast lookup methods for definitions.
"""
import ctypes
import json
import logging
import os
import sqlite3
import tempfile
import threading
import zipfile
from collections import defaultdict

import requests

from constants import (BUNGIE_API_BASE, BUNGIE_REQUIRED_DEFS, DEFAULT_HEADERS,
                       REQUEST_TIMEOUT)
from helpers import normalize_item_hash, retry_request


class ManifestCache:
    """
    Thread-safe singleton for Destiny 2 manifest SQLite DB in ephemeral storage.

    Use ManifestCache.instance() to get the shared instance.
    Call close() when shutting down to release resources and delete the DB file.
    Provides methods for manifest download, update, and lookup.
    """
    _instance = None

    @classmethod
    def instance(cls, *args, **kwargs) -> "ManifestCache":
        """
        Get the thread-safe shared instance of ManifestCache singleton.
        Ensures manifest is loaded and prewarms small tables on first instantiation.

        Returns:
            ManifestCache: Shared singleton instance.
        """
        if not hasattr(cls, "_instance_lock"):
            cls._instance_lock = threading.RLock()
        if cls._instance is None:
            with cls._instance_lock:
                if cls._instance is None:
                    cls._instance = cls(*args, **kwargs)
                    cls._instance.ensure_manifest()
                    cls._instance.prewarm_small_tables()
        # else:
        #     cls._instance.ensure_manifest()
        return cls._instance

    def __del__(self):
        """
        Destructor to ensure resources are released and manifest DB file is deleted.
        """
        self.close()


    def __init__(
        self,
        api_base: str = BUNGIE_API_BASE,
        headers: dict = None,
        timeout: int = REQUEST_TIMEOUT,
        storage_path: str = None
    ):
        """
        Initialize ManifestCache with API base, headers, timeout, and storage path.

        Args:
            api_base (str): Bungie API base URL.
            headers (dict): HTTP headers for requests.
            timeout (int): Request timeout in seconds.
            storage_path (str): Path to store manifest SQLite DB.
        """
        self.api_base = api_base
        self.headers = headers or DEFAULT_HEADERS
        self.timeout = timeout
        self.storage_path = storage_path or "/tmp/manifest.content"
        self.version = None
        self._lock = threading.RLock()
        self._conn = None
        self._memo = defaultdict(dict)   # per-definition in-memory memo for single-hash lookups
        self._small_defs = {}            # fully prewarmed small tables (stat names, energy types, etc.)
        self._warned_single_get_definitions = False  # log deprecation once

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
                        logging.error("No .content file found in manifest ZIP.")
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
                raise FileNotFoundError(f"Manifest DB not found at {self.storage_path}")
            # Open read-only; allow cross-thread reads
            self._conn = sqlite3.connect(f"file:{self.storage_path}?mode=ro", uri=True, check_same_thread=False)
            # Read-only performance PRAGMAs (safe; no writes)
            try:
                self._conn.execute("PRAGMA journal_mode=OFF;")
                self._conn.execute("PRAGMA synchronous=OFF;")
                self._conn.execute("PRAGMA temp_store=MEMORY;")
                self._conn.execute("PRAGMA cache_size=-32768;")    # ~32MB page cache
                self._conn.execute("PRAGMA mmap_size=134217728;")  # 128MB mmap if supported
            except Exception:
                pass
            return self._conn

    def prewarm_small_tables(self) -> None:
        """
        Preload small, frequently used definition tables into memory.
        Avoids per-hash SQLite lookups for common names/types.
        Safe because these tables are tiny (O(10-1000) rows).
        """
        small_types = [
            "DestinyStatDefinition",
            "DestinyEnergyTypeDefinition",
            "DestinyDamageTypeDefinition",
            "DestinyBreakerTypeDefinition",
            "DestinySocketCategoryDefinition",
            "DestinyClassDefinition",
            "DestinyRaceDefinition",
            "DestinyGenderDefinition",
        ]
        with self._lock:
            for t in small_types:
                try:
                    self._small_defs[t] = self.get_all_definitions(t)  # full-table read (small only)
                except Exception:
                    continue

    def get_definitions_batch(self, definition_type: str, item_hashes: list[int | str]) -> dict[str, dict]:
        """
        Batch resolve a list of hashes for a single definition type.
        Returns dict keyed by unsigned string hash -> json dict.

        Args:
            definition_type (str): Manifest table name.
            item_hashes (list[int | str]): List of item hashes to resolve.

        Returns:
            dict: Mapping of hash to definition dict.
        """
        if not item_hashes:
            return {}
        # Normalize and build signed/unsigned sets
        u32s = []
        i32s = []
        seen = set()
        for h in item_hashes:
            try:
                norm = int(normalize_item_hash(h))
            except Exception:
                continue
            if norm in seen:
                continue
            seen.add(norm)
            u32s.append(norm)
            i32s.append(ctypes.c_int32(norm).value)
        # Chunk because SQLite has a limit (~999 parameters)
        def chunks(lst, n=400):
            for i in range(0, len(lst), n):
                yield lst[i:i+n]
        out: dict[str, dict] = {}
        with self._lock:
            conn = self._connect()
            cur = conn.cursor()
            for us, is_ in zip(chunks(u32s), chunks(i32s)):
                params = tuple(us + is_)
                placeholders = ",".join("?" for _ in params)
                try:
                    cur.execute(f"SELECT id, json FROM {definition_type} WHERE id IN ({placeholders})", params)
                    for row in cur.fetchall():
                        try:
                            uid = int(row[0]) & 0xFFFFFFFF
                            out[str(uid)] = json.loads(row[1])
                        except Exception:
                            continue
                except Exception as e:
                    logging.error("Batch manifest lookup failed for %s (%d ids): %s", definition_type, len(params), e)
        return out

    def resolve_exact(self, item_hash: int | str, definition_type: str) -> dict | None:
        """
        Fast path: resolve a single hash against a specific definition.
        Uses per-type memoization to avoid repeated DB hits.

        Args:
            item_hash (int | str): Item hash to resolve.
            definition_type (str): Manifest table name.

        Returns:
            dict or None: Definition dict if found, else None.
        """
        try:
            norm = int(normalize_item_hash(item_hash))
        except Exception:
            return None
        memo = self._memo[definition_type]
        key = str(norm)
        if key in memo:
            return memo[key]
        # direct single-row SQL to avoid get_definitions single-hash path
        with self._lock:
            conn = self._connect()
            cursor = conn.cursor()
            signed_hash = ctypes.c_int32(norm).value
            try:
                cursor.execute(
                    f"SELECT json FROM {definition_type} WHERE id IN (?, ?) LIMIT 1",
                    (signed_hash, norm),
                )
                row = cursor.fetchone()
                if row:
                    result = json.loads(row[0])
                    memo[key] = result
                    return result
            except Exception as e:
                logging.error("Manifest lookup failed for %s (u32=%s, i32=%s): %s", definition_type, norm, signed_hash, e)
        return None

    def resolve_many(self, hashes: list[int | str], definition_type: str) -> dict[str, dict]:
        """
        Fast path: resolve many hashes for one definition type with memo + batch SQL.

        Args:
            hashes (list[int | str]): List of item hashes to resolve.
            definition_type (str): Manifest table name.

        Returns:
            dict: Mapping of hash to definition dict.
        """
        # Partition into (cached) and (misses)
        norm_hashes = []
        misses = []
        memo = self._memo[definition_type]
        for h in hashes:
            try:
                norm = int(normalize_item_hash(h))
            except Exception:
                continue
            norm_hashes.append(norm)
            if str(norm) not in memo:
                misses.append(norm)
        # Batch fetch misses
        if misses:
            fetched = self.get_definitions_batch(definition_type, misses)
            memo.update(fetched)
        # Build output from memo for all requested (including duplicates)
        out = {}
        for n in norm_hashes:
            v = memo.get(str(n))
            if v:
                out[str(n)] = v
        return out

    def get_all_definitions(self, definition_type: str) -> dict:
        """
        Fast full-table read for *small* definition tables.
        Returns a mapping of unsigned string hash -> definition json.

        Args:
            definition_type (str): Manifest table name.

        Returns:
            dict: Mapping of hash to definition dict.
        """
        defs = {}
        with self._lock:
            conn = self._connect()
            cursor = conn.cursor()
            try:
                cursor.execute(f"SELECT id, json FROM {definition_type}")
                for row in cursor.fetchall():
                    try:
                        uid = int(row[0]) & 0xFFFFFFFF
                        defs[str(uid)] = json.loads(row[1])
                    except Exception:
                        continue
            except Exception as e:
                logging.error("Manifest get_all_definitions failed for %s: %s", definition_type, e)
        return defs

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
                # DEPRECATED single-hash path: prefer resolve_exact(...)
                logging.debug("get_definitions(single) is deprecated; use resolve_exact for %s", definition_type)
                norm_hash = normalize_item_hash(item_hash)  # unsigned u32
                # two's complement signed form
                signed_hash = ctypes.c_int32(int(norm_hash)).value
                if not self._warned_single_get_definitions:
                    logging.warning("get_definitions(single) is deprecated; use resolve_exact for %s", definition_type)
                    self._warned_single_get_definitions = True
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
        logging.debug("Attempting to resolve manifest hash: %s across types: %s", item_hash, definition_types if definition_types else BUNGIE_REQUIRED_DEFS)
        if definition_types and len(definition_types) == 1:
            d = definition_types[0]
            hit = self.resolve_exact(item_hash, d)
            return (hit, d) if hit else (None, None)
        if not definition_types:
            definition_types = BUNGIE_REQUIRED_DEFS
        # Try each type with resolve_exact (fast path with memo + direct SQL)
        for def_type in definition_types:
            hit = self.resolve_exact(item_hash, def_type)
            if hit:
                logging.info("Manifest hash %s found in %s.", item_hash, def_type)
                return hit, def_type
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
