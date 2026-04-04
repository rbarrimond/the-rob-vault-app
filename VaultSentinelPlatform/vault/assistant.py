# pylint: disable=line-too-long
"""
Vault Assistant module for Destiny 2.

Provides the `VaultAssistant` class, which encapsulates business logic for:
- OAuth authentication and token refresh with Bungie.net
- Secure storage and retrieval of session tokens using Azure Table Storage
- Fetching and decoding Destiny 2 vault and character data
- Saving and listing DIM (Destiny Item Manager) backups in Azure Blob Storage
- Integration with Azure services for secure, scalable, and maintainable operations

All API interactions, manifest lookups, and backup operations are managed through this class.
"""

import json
import logging
from datetime import UTC, datetime

import requests
from azure.core.exceptions import AzureError
from azure.storage.blob import BlobServiceClient
from requests.exceptions import RequestException
from sqlalchemy.exc import SQLAlchemyError

from VaultSentinelPlatform.agent.db_agent import VaultSentinelDBAgent
from VaultSentinelPlatform.bungie.session_manager import BungieSessionManager
from VaultSentinelPlatform.common.helpers import (
    blob_exists,
    get_blob_last_modified,
    load_blob,
    load_valid_blob,
    retry_request,
    save_blob,
    save_dim_backup_blob,
)
from VaultSentinelPlatform.config import (
    API_KEY,
    BLOB_CONTAINER,
    BUNGIE_API_BASE,
    BUNGIE_REQUIRED_DEFS,
    CLASS_TYPE_MAP,
    REQUEST_TIMEOUT,
    STORAGE_CONNECTION_STRING,
    TABLE_NAME,
)
from VaultSentinelPlatform.exceptions import DependencyUnavailableError
from VaultSentinelPlatform.manifest.cache import ManifestCache
from VaultSentinelPlatform.models import CharacterModel, ItemModel, VaultModel


NO_DESTINY_MEMBERSHIPS_FOUND = "No Destiny memberships found for user."


class VaultAssistant:
    """
    Business logic for Destiny 2 Vault Assistant operations.

    Manages Destiny 2 API interactions, manifest lookups, and backup operations, and delegates
    session/authentication logic to `BungieSessionManager`. Integrates with Azure services for
    secure storage and scalable operations. Supports decoding and persisting Destiny 2 vault and
    character data using `VaultModel` and `CharacterModel`, and can persist decoded data to a
    relational database via ORM models.
    """

    def __init__(
        self,
        api_key: str | None = API_KEY,
        storage_conn_str: str | None = STORAGE_CONNECTION_STRING,
        table_name: str = TABLE_NAME,
        blob_container: str = BLOB_CONTAINER,
        api_base: str = BUNGIE_API_BASE,
        timeout: int = REQUEST_TIMEOUT
    ):
        """
        Initialize a `VaultAssistant` with configuration and dependencies.

        Args:
            api_key (str): Bungie API key.
            storage_conn_str (str): Azure Storage connection string.
            table_name (str): Azure Table name for session storage.
            blob_container (str): Azure Blob container name.
            api_base (str): Bungie API base URL.
            timeout (int): HTTP request timeout in seconds.
        """
        self.api_key = api_key or ""
        self.storage_conn_str = storage_conn_str or ""
        self.table_name = table_name
        self.blob_container = blob_container
        self.api_base = api_base
        self.timeout = timeout
        self.manifest_cache = ManifestCache.instance()
        self.session_manager = BungieSessionManager.instance()
        # DB agent is provided via factory (on-demand); do not construct here to avoid cold-start hangs.

    def _build_headers(self, access_token: str) -> dict[str, str]:
        """Build the standard Bungie API headers for the current request."""
        return {
            "Authorization": f"Bearer {access_token}",
            "X-API-Key": self.api_key,
        }

    @staticmethod
    def _page_items(items: list[dict], limit: int | None, offset: int) -> list[dict]:
        """Return a paginated slice of an item list."""
        return items[offset:offset + limit] if limit is not None else items[offset:]

    @staticmethod
    def _should_sync_decoded_payload(force_refresh: bool, limit: int | None, offset: int) -> bool:
        """Return True when the full decoded dataset should also be persisted."""
        return force_refresh or (limit is None and offset == 0)

    @staticmethod
    def _serialize_item_models(item_models, include_perks: bool) -> list[dict]:
        """Serialize decoded item models while optionally omitting perk details."""
        serialized_items: list[dict] = []
        for item in item_models:
            item_dict = item.model_dump()
            if not include_perks:
                item_dict.pop("perks", None)
            serialized_items.append(item_dict)
        return serialized_items

    def _fetch_item_components_map(
        self,
        membership_id: str,
        membership_type: str,
        headers: dict[str, str],
        *,
        context: str,
    ) -> dict[str, dict]:
        """Fetch and merge Bungie item components, returning an empty mapping on failure."""
        components_url = (
            f"{self.api_base}/Destiny2/{membership_type}/Profile/{membership_id}/?components="
            "300,302,304,305,310"
        )
        try:
            components_resp = retry_request(
                requests.get,
                components_url,
                headers=headers,
                timeout=self.timeout,
            )
        except (RequestException, RuntimeError, ValueError) as exc:
            logging.warning("Error fetching item components for %s: %s", context, exc)
            return {}

        if not components_resp.ok:
            logging.warning(
                "Failed to fetch item components for %s. Status: %d",
                context,
                components_resp.status_code,
            )
            return {}

        components_payload = components_resp.json().get("Response", {}).get("itemComponents", {})
        return self._merge_item_components(components_payload)

    def _build_character_profile(
        self,
        char_id: str,
        char_info: dict,
        inventory_data: dict,
        artifact_hash: int | None,
        artifact_power_bonus: int | None,
    ) -> dict:
        """Build a manifest-enriched character payload from Bungie character data."""
        race_hash = char_info.get("raceHash")
        class_hash = char_info.get("classHash")
        gender_hash = char_info.get("genderHash")
        race_def = self.manifest_cache.resolve_exact(race_hash, "DestinyRaceDefinition") if race_hash else None
        class_def = self.manifest_cache.resolve_exact(class_hash, "DestinyClassDefinition") if class_hash else None
        gender_def = self.manifest_cache.resolve_exact(gender_hash, "DestinyGenderDefinition") if gender_hash else None

        enriched_character = {
            "characterId": char_id,
            "class": class_def["displayProperties"]["name"] if class_def else None,
            "race": race_def["displayProperties"]["name"] if race_def else None,
            "gender": gender_def["displayProperties"]["name"] if gender_def else None,
            "light": char_info.get("light"),
            "emblem": char_info.get("emblemPath"),
            "emblemBackground": char_info.get("emblemBackgroundPath"),
            "level": char_info.get("baseCharacterLevel"),
            "lastPlayed": char_info.get("dateLastPlayed"),
            "items": inventory_data.get(char_id, {}).get("items", []),
        }
        if artifact_hash is not None:
            enriched_character["artifact"] = {
                "itemHash": artifact_hash,
                "powerBonus": artifact_power_bonus,
            }
        return enriched_character

    def _decode_character_payload(
        self,
        char_data: dict,
        components_map: dict[str, dict],
        include_perks: bool,
        limit: int | None,
        offset: int,
    ) -> tuple[CharacterModel, dict, dict]:
        """Decode one stored character payload into full and paged response forms."""
        char_items = char_data.get("items", [])
        char_data_no_items = {k: v for k, v in char_data.items() if k != "items"}
        artifact_raw = char_data.get("artifact") if isinstance(char_data.get("artifact"), dict) else None
        char_model = CharacterModel.from_components(
            char_data_no_items,
            char_items,
            components_map,
            artifact_raw=artifact_raw,
        )

        full_char_dict = char_model.model_dump()
        full_items = self._serialize_item_models(char_model.items, include_perks)
        full_char_dict["items"] = full_items
        paged_char_dict = dict(full_char_dict)
        paged_char_dict["items"] = self._page_items(full_items, limit, offset)
        return char_model, full_char_dict, paged_char_dict

    @staticmethod
    def _merge_item_components(component_payload: dict | None) -> dict[str, dict]:
        """
        Combine item component sections into a single instance-id keyed mapping.

        Args:
            component_payload (dict | None): The `itemComponents` payload from Bungie API Response,
                typically containing sections like `instances`, `stats`, `perks`, `sockets`, and `reusablePlugs`.

        Returns:
            dict[str, dict]: Mapping of itemInstanceId to a combined structure of available components.
        """
        if not component_payload:
            return {}
        combined: dict[str, dict] = {}
        mapping = {
            "instances": "instance",
            "stats": "stats",
            "perks": "perks",
            "sockets": "sockets",
            "reusablePlugs": "reusablePlugs",
        }
        for source_key, target_key in mapping.items():
            data_section = component_payload.get(source_key, {}) or {}
            data_map = data_section.get("data", {}) if isinstance(data_section, dict) else {}
            for instance_id, payload in (data_map or {}).items():
                key = str(instance_id)
                entry = combined.setdefault(key, {})
                entry[target_key] = {"data": payload}
        return combined


    # Session/auth methods are now delegated to BungieSessionManager
    def exchange_code_for_token(self, code: str) -> dict:
        """
        Exchange OAuth authorization code for access/refresh tokens, store them, and return token data.

        Args:
            code (str): OAuth authorization code.

        Returns:
            dict: Token data returned from the Bungie API.
        """
        return self.session_manager.exchange_code_for_token(code)

    def get_session(self) -> dict:
        """
        Retrieve stored session info including access token and membership details.

        Returns:
            dict: Session info with access token and membership identifiers.
        """
        return self.session_manager.get_session()

    def refresh_token(self, refresh_token_val: str) -> tuple[dict, int]:
        """
        Refresh the access token using the provided refresh token value.

        Args:
            refresh_token_val (str): The refresh token value.

        Returns:
            tuple[dict, int]: A tuple of (token_data, status_code).
        """
        return self.session_manager.refresh_token(refresh_token_val)

    def initialize_user(self) -> tuple[dict | None, int]:
        """
        Authenticate user (via session), ensure manifest readiness, and fetch Destiny 2 character summary.

        Returns:
            tuple[dict | None, int]: On success, a tuple of (user summary dict, 200). On error, (None, status_code).
        """
        session = self.get_session()
        access_token = session["access_token"]
        membership_id = session["membership_id"]
        membership_type = session["membership_type"]
        if not all([membership_id, membership_type]):
            logging.error(NO_DESTINY_MEMBERSHIPS_FOUND)
            return None, 404

        manifest_ready = self.manifest_cache.ensure_manifest()
        headers = self._build_headers(access_token)
        characters_url = f"{self.api_base}/Destiny2/{membership_type}/Profile/{membership_id}/?components=200"
        char_resp = retry_request(requests.get, characters_url, headers=headers, timeout=self.timeout)
        if not char_resp.ok:
            logging.error("Failed to get characters: status %d", char_resp.status_code)
            return None, char_resp.status_code

        characters_data = char_resp.json()["Response"]["characters"]["data"]
        character_summary = {}
        for char_id, char in characters_data.items():
            class_type = char["classType"]
            race_hash = char["raceHash"]
            class_name = CLASS_TYPE_MAP.get(class_type, str(class_type))
            race_def = self.manifest_cache.resolve_exact(race_hash, "DestinyRaceDefinition")
            race_name = race_def.get("displayProperties", {}).get("name") if race_def else str(race_hash)
            character_summary[char_id] = {
                "classType": class_type,
                "className": class_name,
                "light": char["light"],
                "raceHash": race_hash,
                "raceName": race_name,
            }

        logging.info("User initialized successfully: %s", membership_id)
        return {
            "message": "Assistant initialized.",
            "membershipId": membership_id,
            "membershipType": membership_type,
            "characters": character_summary,
            "manifestReady": manifest_ready,
        }, 200

    def get_bungie_profile_last_modified(self, membership_id: str, membership_type: str, headers: dict) -> tuple[datetime | None, int]:
        """
        Fetch the Bungie profile's last modified date as a timezone-naive UTC datetime.

        Args:
            membership_id (str): Destiny 2 membership ID.
            membership_type (str): Destiny 2 membership type.
            headers (dict): Headers to include in the request.

        Returns:
            tuple[datetime | None, int]: A tuple of (last_modified_utc, status_code). If not available, datetime is None.
        """
        get_profile_url = f"{self.api_base}/Destiny2/{membership_type}/Profile/{membership_id}/?components=100"
        profile_detail_resp = retry_request(requests.get, get_profile_url, headers=headers, timeout=self.timeout)
        if not profile_detail_resp.ok:
            logging.error("Failed to get profile details: status %d", profile_detail_resp.status_code)
            return None, profile_detail_resp.status_code
        profile_detail = profile_detail_resp.json()["Response"]["profile"]["data"]
        bungie_last_modified = profile_detail.get("dateLastPlayed") or profile_detail.get("lastModified")
        if bungie_last_modified:
            try:
                bungie_last_modified_dt = datetime.strptime(bungie_last_modified, "%Y-%m-%dT%H:%M:%SZ")
            except ValueError:
                logging.warning(
                    "Unable to parse Bungie profile timestamp '%s' for membership %s.",
                    bungie_last_modified,
                    membership_id,
                )
                bungie_last_modified_dt = None
        else:
            bungie_last_modified_dt = None
        return bungie_last_modified_dt, 200

    def process_query(self, query: dict) -> dict:
        """
        Process a Destiny 2 gear query using `VaultSentinelDBAgent`.

        Args:
            query (dict): Query conforming to the Vault Sentinel schema.

        Returns:
            dict: Agent response payload.

        Raises:
            DependencyUnavailableError: If the backing DB agent cannot serve the request.
        """
        try:
            agent = VaultSentinelDBAgent.instance()
        except RuntimeError as exc:
            logging.error("Failed to obtain DB agent instance: %s", exc, exc_info=True)
            raise DependencyUnavailableError(
                "DB agent unavailable. Check configuration and logs.",
                details={"dependency": "vault_sentinel_db_agent"},
            ) from exc
        if not getattr(agent, "session_factory", None):
            logging.error("DB agent session factory not initialized.")
            raise DependencyUnavailableError(
                "Database not configured.",
                details={"dependency": "database_session_factory"},
            )
        return agent.process_query(query)

    def get_vault(self) -> tuple[list, int] | tuple[None, int]:
        """
        Fetch the user's Destiny 2 vault inventory efficiently, using blob cache when up-to-date.

        Compares the blob's last modified date with the Bungie profile's lastModified before fetching inventory.

        Returns:
            tuple[list, int] | tuple[None, int]: (inventory list, 200) on success; otherwise (None, status_code).
        """
        session = self.get_session()
        access_token = session["access_token"]
        membership_id = session["membership_id"]
        membership_type = session["membership_type"]
        if not all([membership_id, membership_type]):
            logging.error(NO_DESTINY_MEMBERSHIPS_FOUND)
            return None, 404

        headers = self._build_headers(access_token)
        bungie_last_modified_dt, status = self.get_bungie_profile_last_modified(membership_id, membership_type, headers)
        if status != 200:
            return None, status

        blob_name = f"{membership_id}.json"
        blob_last_modified_dt = get_blob_last_modified(self.storage_conn_str, self.blob_container, blob_name)
        if (
            blob_exists(self.storage_conn_str, self.blob_container, blob_name)
            and bungie_last_modified_dt
            and blob_last_modified_dt
            and blob_last_modified_dt >= bungie_last_modified_dt
        ):
            logging.info("Using cached vault inventory from blob for user: %s", membership_id)
            blob_data = load_blob(self.storage_conn_str, self.blob_container, blob_name)
            if blob_data is not None:
                return json.loads(blob_data), 200

        inventory_url = f"{self.api_base}/Destiny2/{membership_type}/Profile/{membership_id}/?components=102"
        inv_resp = retry_request(requests.get, inventory_url, headers=headers, timeout=self.timeout)
        if not inv_resp.ok:
            logging.error("Failed to get vault inventory: status %d", inv_resp.status_code)
            return None, inv_resp.status_code

        inventory = inv_resp.json()["Response"]["profileInventory"]["data"]["items"]
        save_blob(self.storage_conn_str, self.blob_container, blob_name, json.dumps(inventory))
        logging.info("Vault inventory fetched and saved for user: %s", membership_id)
        return inventory, 200

    def get_characters(self) -> tuple[dict, int] | tuple[None, int]:
        """
        Fetch the user's character inventories and save to blob storage, using cached data when up-to-date.

        Returns:
            tuple[dict, int] | tuple[None, int]: (inventories dict, 200) on success; otherwise (None, status_code).
        """
        session = self.get_session()
        access_token = session["access_token"]
        membership_id = session["membership_id"]
        membership_type = session["membership_type"]
        if not all([membership_id, membership_type]):
            logging.error(NO_DESTINY_MEMBERSHIPS_FOUND)
            return None, 404

        headers = self._build_headers(access_token)
        bungie_last_modified_dt, status = self.get_bungie_profile_last_modified(membership_id, membership_type, headers)
        if status != 200:
            return None, status

        blob_name = f"{membership_id}-characters.json"
        blob_last_modified_dt = get_blob_last_modified(self.storage_conn_str, self.blob_container, blob_name)
        if (
            blob_exists(self.storage_conn_str, self.blob_container, blob_name)
            and bungie_last_modified_dt
            and blob_last_modified_dt
            and blob_last_modified_dt >= bungie_last_modified_dt
        ):
            logging.info("Using cached character inventories from blob for user: %s", membership_id)
            blob_data = load_blob(self.storage_conn_str, self.blob_container, blob_name)
            if blob_data is not None:
                return json.loads(blob_data), 200

        char_url = f"{self.api_base}/Destiny2/{membership_type}/Profile/{membership_id}/?components=200,201,900"
        char_resp = retry_request(requests.get, char_url, headers=headers, timeout=self.timeout)
        if not char_resp.ok:
            logging.error("Failed to get character data: status %d", char_resp.status_code)
            return None, char_resp.status_code

        resp_json = char_resp.json()["Response"]
        char_data = resp_json["characters"]["data"]
        inventory_data = resp_json["characterInventories"]["data"]
        profile_prog = resp_json.get("profileProgression", {}).get("data", {}) or {}
        seasonal_artifact = profile_prog.get("seasonalArtifact", {}) or {}
        artifact_hash = seasonal_artifact.get("artifactItemHash")
        artifact_power_bonus = seasonal_artifact.get("powerBonus")

        enriched = {
            char_id: self._build_character_profile(
                char_id,
                char_info,
                inventory_data,
                artifact_hash,
                artifact_power_bonus,
            )
            for char_id, char_info in char_data.items()
        }
        save_blob(self.storage_conn_str, self.blob_container, blob_name, json.dumps(enriched))
        logging.info("Character inventories (enriched) fetched and saved for user: %s", membership_id)
        return enriched, 200

    def get_manifest_item(self, item_hash: str | int, definition_type: str | None = None) -> tuple[dict | None, int]:
        """
        Resolve a Destiny 2 item hash against manifest definitions.

        Args:
            item_hash (str | int): Item hash to resolve (string or integer).
            definition_type (str, optional): Manifest definition type to search in. If None, all loaded types are searched.

        Returns:
            tuple[dict | None, int]: (definition dict, 200) if found; otherwise (None, 404).
        """
        if definition_type:
            definition = self.manifest_cache.resolve_exact(item_hash, definition_type)
            return (definition, 200) if definition else (None, 404)

        for def_type in BUNGIE_REQUIRED_DEFS:
            definition = self.manifest_cache.resolve_exact(item_hash, def_type)
            if definition:
                return definition, 200
        return None, 404

    def save_dim_backup(self, membership_id: str, dim_json_str: str) -> tuple[dict, int]:
        """
        Save a DIM backup and its metadata to blob storage and table storage.

        Args:
            membership_id (str): Destiny 2 membership ID.
            dim_json_str (str): DIM backup JSON content as a string.

        Returns:
            tuple[dict, int]: (result dict, 200) on success; error tuple otherwise.
        """
        logging.info("Saving DIM backup for user: %s", membership_id)
        timestamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
        blob_name, hash_key, timestamp = save_dim_backup_blob(
            self.storage_conn_str, self.table_name, membership_id, dim_json_str, timestamp=timestamp)
        logging.info("DIM backup saved for user: %s", membership_id)
        return {
            "message": "DIM backup saved successfully.",
            "blob": blob_name,
            "hash": hash_key,
            "timestamp": timestamp
        }, 200

    def list_dim_backups(self, membership_id: str) -> tuple[dict, int]:
        """
        List available DIM backups for a given membership ID.

        Args:
            membership_id (str): Destiny 2 membership ID.

        Returns:
            tuple[dict, int]: (backups dict, 200) on success; error tuple otherwise.
        """
        logging.info("Listing DIM backups for user: %s", membership_id)
        blob_service = BlobServiceClient.from_connection_string(
            self.storage_conn_str)
        container = blob_service.get_container_client("dim-backups")
        blobs = container.list_blobs(
            name_starts_with=f"dim-backup-{membership_id}-")
        blob_names = [blob.name for blob in blobs]
        logging.info("Found %d DIM backups for user: %s",
                     len(blob_names), membership_id)
        return {"backups": blob_names}, 200

    def decode_vault(
        self,
        include_perks: bool = False,
        limit: int | None = None,
        offset: int = 0,
        *,
        force_refresh: bool = False,
    ) -> tuple[list, int]:
        """
        Decode the vault inventory using `VaultModel.from_components` for each item.

        Optionally include perks and support pagination via offset/limit. Loads the user's vault inventory from blob
        storage, decodes it via `VaultModel`, and returns a list of enriched item dicts. The decoded vault can be
        persisted to a database using the ORM `Vault` and `Item` models.

        Args:
            include_perks (bool): If True, include perks for each item. Defaults to False.
            limit (int | None): Max number of items to return. Defaults to None (no limit).
            offset (int): Number of items to skip. Defaults to 0.
            force_refresh (bool): If True, bypass cached decoded blobs and rebuild data. Defaults to False.

        Returns:
            tuple[list, int]: (decoded items list, 200) on success; error tuple otherwise.
        """
        session = self.get_session()
        membership_id = session["membership_id"]
        membership_type = session["membership_type"]
        headers = self._build_headers(session["access_token"])

        decoded_blob_name = f"{membership_id}-vault-decoded.json"
        date_last_played, _ = self.get_bungie_profile_last_modified(membership_id, membership_type, headers)
        if not force_refresh and date_last_played:
            blob_data = load_valid_blob(
                self.storage_conn_str,
                self.blob_container,
                decoded_blob_name,
                date_last_played,
            )
            if blob_data is not None:
                logging.info("Using cached decoded vault from blob for user: %s", membership_id)
                decoded_items = json.loads(blob_data)
                return self._page_items(decoded_items, limit, offset), 200

        logging.info("Decoding vault inventory for user: %s", membership_id)
        blob_name = f"{membership_id}.json"
        blob_data = load_blob(self.storage_conn_str, self.blob_container, blob_name)
        if blob_data is None:
            logging.error("Vault blob not found for user: %s", membership_id)
            return [], 404

        items = json.loads(blob_data)
        components_map = self._fetch_item_components_map(
            membership_id,
            membership_type,
            headers,
            context="vault decode",
        )
        vault_model = VaultModel.from_components(items, components_map)
        decoded_items_full = self._serialize_item_models(vault_model.items, include_perks)
        paged_items = self._page_items(decoded_items_full, limit, offset)
        should_sync = self._should_sync_decoded_payload(force_refresh, limit, offset)

        if VaultSentinelDBAgent.is_db_configured() and should_sync:
            try:
                db_agent = VaultSentinelDBAgent.instance()
                if getattr(db_agent, "session_factory", None):
                    db_agent.persist_vault(vault_model, membership_id, membership_type)
            except (DependencyUnavailableError, SQLAlchemyError) as exc:  # type: ignore[arg-type]
                logging.warning(
                    "Skipping DB persist_vault because the database dependency is unavailable: %s",
                    exc,
                    exc_info=True,
                )

        if should_sync:
            save_blob(self.storage_conn_str, self.blob_container, decoded_blob_name, json.dumps(decoded_items_full))
        return paged_items, 200

    def decode_characters(
        self,
        include_perks: bool = False,
        limit: int | None = None,
        offset: int = 0,
        *,
        force_refresh: bool = False,
    ) -> tuple[list, int]:
        """
        Decode character equipment using `CharacterModel.from_components` for each character.

        Optionally include perks and support pagination via offset/limit. Loads the user's character inventories from
        blob storage, decodes each character via `CharacterModel`, and returns a list of enriched character dicts.
        Decoded character inventories can be persisted to a database using the ORM `Character` and `Item` models.

        Args:
            include_perks (bool): If True, include perks for each item. Defaults to False.
            limit (int | None): Max number of items to return per character. Defaults to None (no limit).
            offset (int): Number of items to skip per character. Defaults to 0.
            force_refresh (bool): If True, bypass cached decoded blobs and rebuild data. Defaults to False.

        Returns:
            tuple[list, int]: (decoded characters list, 200) on success; error tuple otherwise.
        """
        session = self.get_session()
        membership_id = session["membership_id"]
        membership_type = session["membership_type"]
        headers = self._build_headers(session["access_token"])

        decoded_blob_name = f"{membership_id}-characters-decoded.json"
        date_last_played, _ = self.get_bungie_profile_last_modified(membership_id, membership_type, headers)
        if not force_refresh and date_last_played:
            blob_data = load_valid_blob(
                self.storage_conn_str,
                self.blob_container,
                decoded_blob_name,
                date_last_played,
            )
            if blob_data is not None:
                logging.info("Using cached decoded characters from blob for user: %s", membership_id)
                return json.loads(blob_data), 200

        logging.info("Decoding character inventories for user: %s", membership_id)
        blob_name = f"{membership_id}-characters.json"
        blob_data = load_blob(self.storage_conn_str, self.blob_container, blob_name)
        if blob_data is None:
            logging.error("Character blob not found for user: %s", membership_id)
            return [], 404

        raw = json.loads(blob_data)
        if not isinstance(raw, dict):
            logging.error("Unexpected characters blob format (expected dict of characterId->{items}).")
            return [], 400

        components_map = self._fetch_item_components_map(
            membership_id,
            membership_type,
            headers,
            context="character decode",
        )
        decoded_characters_full: list[dict] = []
        decoded_characters_page: list[dict] = []
        character_models = []
        for char_data in raw.values():
            char_model, full_char_dict, paged_char_dict = self._decode_character_payload(
                char_data,
                components_map,
                include_perks,
                limit,
                offset,
            )
            character_models.append(char_model)
            decoded_characters_full.append(full_char_dict)
            decoded_characters_page.append(paged_char_dict)

        should_sync = self._should_sync_decoded_payload(force_refresh, limit, offset)
        if VaultSentinelDBAgent.is_db_configured() and should_sync:
            try:
                db_agent = VaultSentinelDBAgent.instance()
                if getattr(db_agent, "session_factory", None):
                    db_agent.persist_characters(character_models, membership_id, membership_type)
            except (DependencyUnavailableError, SQLAlchemyError) as exc:  # type: ignore[arg-type]
                logging.warning(
                    "Skipping DB persist_characters because the database dependency is unavailable: %s",
                    exc,
                    exc_info=True,
                )
        if should_sync:
            save_blob(self.storage_conn_str, self.blob_container, decoded_blob_name, json.dumps(decoded_characters_full))

        return decoded_characters_page, 200

    def get_session_token(self) -> tuple[dict, int]:
        """
        Return the current access token and membership ID, wrapped for external use.

        Returns:
            tuple[dict, int]: (session dict, 200) where the dict contains `access_token` and `membership_id`.
        """
        session = self.get_session()
        return {
            "access_token": session["access_token"],
            "membership_id": session["membership_id"]
        }, 200

    def save_object(self, mime_object) -> tuple[dict, int]:
        """
        Save a MIME-like object (file-like) to Azure Blob Storage using `save_blob` helper.

        The object should expose the attributes `filename`, `content_type`, and `content`.

        Args:
            mime_object: An object with `filename` (str), `content_type` (str | None), and `content` (bytes/str).

        Returns:
            tuple[dict, int]: (result dict, 200) on success; error tuple otherwise.
        """
        logging.info("Saving MIME object to blob storage.")
        filename = getattr(mime_object, 'filename', None)
        content_type = getattr(mime_object, 'content_type', None)
        content = getattr(mime_object, 'content', None)
        if not filename or not content:
            logging.error("MIME object missing filename or content.")
            return {"error": "Missing filename or content in MIME object."}, 400
        try:
            if content_type:
                save_blob(self.storage_conn_str, self.blob_container, filename, content, content_type=content_type)
            else:
                save_blob(self.storage_conn_str, self.blob_container, filename, content)
            container_url = BlobServiceClient.from_connection_string(self.storage_conn_str).get_container_client(self.blob_container).url
            blob_url = f"{container_url}/{filename}"
            logging.info("Saved MIME object as blob: %s", blob_url)
            return {"message": "Object saved successfully.", "blob": filename, "url": blob_url}, 200
        except (AzureError, TypeError, ValueError) as exc:  # type: ignore[arg-type]
            logging.error("Failed to save MIME object: %s", exc, exc_info=True)
            return {"error": "Failed to save object. Check logs."}, 500

    def get_item_full_info(self, item_hash: str, item_instance_id: str | None = None) -> tuple[dict | None, int]:
        """
        Retrieve full information for an item, including perks, stats, and other properties.

        If `item_instance_id` is provided, fetch instance-specific data (e.g., rolled perks, stats).

        Args:
            item_hash (str): Destiny 2 item hash.
            item_instance_id (str, optional): Destiny 2 item instance ID.

        Returns:
            tuple[dict | None, int]: (item info dict, 200) if found; otherwise (None, 404).
        """
        raw_data = {
            "itemHash": item_hash,
            "itemInstanceId": item_instance_id
        }
        item_model = ItemModel.from_components(raw_data)
        if item_model.itemName == "Unknown":
            logging.error("Item hash %s not found in manifest.", item_hash)
            return None, 404
        return item_model.model_dump(), 200
