"""Typed SQLite query service for Bungie's native manifest database."""

from __future__ import annotations

import ctypes
import json
import logging
import os
import sqlite3
import threading
from collections import defaultdict
from typing import Any, Optional, Sequence

from constants import BUNGIE_REQUIRED_DEFS
from helpers import normalize_item_hash
from VaultSentinelPlatform.exceptions import DependencyUnavailableError


class ManifestSQLiteQueryService:
    """Provide typed, memoized manifest queries against a local SQLite `.content` file."""

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._conn: sqlite3.Connection | None = None
        self._memo = defaultdict(dict)
        self._small_defs: dict[str, dict[str, dict]] = {}
        self._warned_single_get_definitions = False

    def _connect(self) -> sqlite3.Connection:
        """Open the manifest SQLite database in read-only mode."""
        with self._lock:
            if self._conn is not None:
                return self._conn
            if not os.path.exists(self.db_path):
                raise DependencyUnavailableError(
                    f"Manifest DB not found at {self.db_path}",
                    details={"db_path": self.db_path},
                )
            self._conn = sqlite3.connect(
                f"file:{self.db_path}?mode=ro",
                uri=True,
                check_same_thread=False,
            )
            try:
                self._conn.execute("PRAGMA journal_mode=OFF;")
                self._conn.execute("PRAGMA synchronous=OFF;")
                self._conn.execute("PRAGMA temp_store=MEMORY;")
                self._conn.execute("PRAGMA cache_size=-32768;")
                self._conn.execute("PRAGMA mmap_size=134217728;")
            except sqlite3.Error:
                logging.debug("SQLite performance pragmas were not fully applied.")
            return self._conn

    def connect(self) -> sqlite3.Connection:
        """Return the active SQLite connection through a public API."""
        return self._connect()

    @staticmethod
    def _decode_definition_row(row: Sequence[Any]) -> tuple[str, dict] | None:
        """Decode a manifest row into a normalized hash key and JSON payload."""
        try:
            return str(int(row[0]) & 0xFFFFFFFF), json.loads(row[1])
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _chunk(values: Sequence[int], chunk_size: int = 400):
        """Yield list slices that respect SQLite parameter limits."""
        for index in range(0, len(values), chunk_size):
            yield values[index:index + chunk_size]

    def close(self) -> None:
        """Close the SQLite connection."""
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None

    def prewarm_small_tables(self) -> None:
        """Preload small, frequently used definition tables into memory."""
        for definition_type in (
            "DestinyStatDefinition",
            "DestinyEnergyTypeDefinition",
            "DestinyDamageTypeDefinition",
            "DestinyBreakerTypeDefinition",
            "DestinySocketCategoryDefinition",
            "DestinyClassDefinition",
            "DestinyRaceDefinition",
            "DestinyGenderDefinition",
        ):
            try:
                self._small_defs[definition_type] = self.get_all_definitions(definition_type)
            except (sqlite3.Error, ValueError, TypeError):
                logging.debug("Skipping manifest prewarm for %s.", definition_type)

    @staticmethod
    def _normalize_hash_value(item_hash: int | str) -> int:
        return int(normalize_item_hash(item_hash))

    def get_definitions_batch(
        self,
        definition_type: str,
        item_hashes: Sequence[int | str],
    ) -> dict[str, dict]:
        """Batch resolve a list of hashes for one manifest definition table."""
        if not item_hashes:
            return {}

        unsigned_hashes: list[int] = []
        signed_hashes: list[int] = []
        seen: set[int] = set()
        for item_hash in item_hashes:
            try:
                normalized = self._normalize_hash_value(item_hash)
            except (TypeError, ValueError):
                continue
            if normalized in seen:
                continue
            seen.add(normalized)
            unsigned_hashes.append(normalized)
            signed_hashes.append(ctypes.c_int32(normalized).value)

        resolved: dict[str, dict] = {}
        with self._lock:
            cursor = self.connect().cursor()
            for unsigned_chunk, signed_chunk in zip(
                self._chunk(unsigned_hashes),
                self._chunk(signed_hashes),
            ):
                parameters = tuple(list(unsigned_chunk) + list(signed_chunk))
                placeholders = ",".join("?" for _ in parameters)
                try:
                    cursor.execute(
                        f"SELECT id, json FROM {definition_type} WHERE id IN ({placeholders})",
                        parameters,
                    )
                    for row in cursor.fetchall():
                        decoded = self._decode_definition_row(row)
                        if decoded is not None:
                            hash_key, definition = decoded
                            resolved[hash_key] = definition
                except sqlite3.Error as exc:
                    logging.error(
                        "Batch manifest lookup failed for %s (%d ids): %s",
                        definition_type,
                        len(parameters),
                        exc,
                    )
        return resolved

    def resolve_exact(self, item_hash: int | str, definition_type: str) -> dict | None:
        """Resolve a single hash against a known manifest definition table."""
        try:
            normalized = self._normalize_hash_value(item_hash)
        except (TypeError, ValueError):
            return None

        memo = self._memo[definition_type]
        memo_key = str(normalized)
        if memo_key in memo:
            return memo[memo_key]

        with self._lock:
            cursor = self._connect().cursor()
            signed_hash = ctypes.c_int32(normalized).value
            try:
                cursor.execute(
                    f"SELECT json FROM {definition_type} WHERE id IN (?, ?) LIMIT 1",
                    (signed_hash, normalized),
                )
                row = cursor.fetchone()
                if row:
                    result = json.loads(row[0])
                    memo[memo_key] = result
                    return result
            except (sqlite3.Error, TypeError, ValueError) as exc:
                logging.error(
                    "Manifest lookup failed for %s (u32=%s, i32=%s): %s",
                    definition_type,
                    normalized,
                    signed_hash,
                    exc,
                )
        return None

    def resolve_many(self, hashes: Sequence[int | str], definition_type: str) -> dict[str, dict]:
        """Resolve multiple hashes for one manifest definition table with memoization."""
        memo = self._memo[definition_type]
        normalized_hashes: list[int] = []
        misses: list[int] = []

        for item_hash in hashes:
            try:
                normalized = self._normalize_hash_value(item_hash)
            except (TypeError, ValueError):
                continue
            normalized_hashes.append(normalized)
            if str(normalized) not in memo:
                misses.append(normalized)

        if misses:
            memo.update(self.get_definitions_batch(definition_type, misses))

        resolved: dict[str, dict] = {}
        for normalized in normalized_hashes:
            hit = memo.get(str(normalized))
            if hit is not None:
                resolved[str(normalized)] = hit
        return resolved

    def get_all_definitions(self, definition_type: str) -> dict[str, dict]:
        """Return every definition for a manifest table, keyed by normalized hash."""
        definitions: dict[str, dict] = {}
        with self._lock:
            cursor = self._connect().cursor()
            try:
                cursor.execute(f"SELECT id, json FROM {definition_type}")
                for row in cursor.fetchall():
                    decoded = self._decode_definition_row(row)
                    if decoded is not None:
                        hash_key, definition = decoded
                        definitions[hash_key] = definition
            except sqlite3.Error as exc:
                logging.error(
                    "Manifest get_all_definitions failed for %s: %s",
                    definition_type,
                    exc,
                )
        return definitions

    def get_definitions(self, definition_type: str, item_hash: str | int | None = None) -> dict | None:
        """Compatibility method retained for callers that still use the old API."""
        if item_hash is not None:
            if not self._warned_single_get_definitions:
                logging.warning(
                    "get_definitions(single) is deprecated; use resolve_exact for %s",
                    definition_type,
                )
                self._warned_single_get_definitions = True
            return self.resolve_exact(item_hash, definition_type)
        return self.get_all_definitions(definition_type)

    def resolve_manifest_hash(
        self,
        item_hash: int | str,
        definition_types: Optional[list[str]] = None,
    ) -> tuple[dict | None, str | None]:
        """Resolve a hash across one or more manifest definition tables."""
        definition_types = definition_types or BUNGIE_REQUIRED_DEFS
        if len(definition_types) == 1:
            definition_type = definition_types[0]
            definition = self.resolve_exact(item_hash, definition_type)
            return (definition, definition_type) if definition else (None, None)

        for definition_type in definition_types:
            definition = self.resolve_exact(item_hash, definition_type)
            if definition is not None:
                return definition, definition_type
        return None, None

    def search_definitions_by_name(
        self,
        definition_type: str,
        query_text: str,
        *,
        limit: int = 25,
    ) -> list[dict[str, Any]]:
        """Search a manifest table by display name using SQLite-backed filtering."""
        normalized_query = (query_text or "").strip().lower()
        if not normalized_query:
            return []

        matches: list[dict[str, Any]] = []
        pattern = f"%{normalized_query}%"
        with self._lock:
            cursor = self._connect().cursor()
            try:
                cursor.execute(
                    f"SELECT json FROM {definition_type} WHERE lower(json) LIKE ? LIMIT ?",
                    (pattern, limit),
                )
                rows = cursor.fetchall()
            except sqlite3.Error as exc:
                logging.error(
                    "Manifest name search failed for %s: %s",
                    definition_type,
                    exc,
                )
                return []

        for row in rows:
            try:
                definition = json.loads(row[0])
            except (TypeError, ValueError):
                continue
            display_name = ((definition or {}).get("displayProperties") or {}).get("name", "")
            if normalized_query in display_name.lower():
                matches.append(definition)
        return matches
