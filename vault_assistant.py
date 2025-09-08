# pylint: disable=line-too-long,broad-exception-caught
"""
Vault Assistant module for Destiny 2.

This module provides the VaultAssistant class, which encapsulates business logic for:
- OAuth authentication and token refresh with Bungie.net
- Secure storage and retrieval of session tokens using Azure Table Storage
- Fetching and decoding Destiny 2 vault and character data
- Saving and listing DIM (Destiny Item Manager) backups in Azure Blob Storage
- Integration with Azure services for secure, scalable, and maintainable operations

All API interactions, manifest lookups, and backup operations are managed through this class.
"""
import json
import logging
from datetime import datetime

import requests
from azure.storage.blob import BlobServiceClient

from bungie_session_manager import BungieSessionManager
from helpers import (blob_exists, get_blob_last_modified, load_blob_if_stale,
    retry_request, load_blob, save_blob, save_dim_backup_blob)
from manifest_cache import ManifestCache
from constants import BUNGIE_REQUIRED_DEFS, CLASS_TYPE_MAP
from constants import (
    API_KEY,
    STORAGE_CONNECTION_STRING,
    TABLE_NAME,
    BLOB_CONTAINER,
    BUNGIE_API_BASE,
    REQUEST_TIMEOUT
)
from models import ItemModel, VaultModel, CharacterModel

class VaultAssistant:
    """
    Main business logic for Destiny 2 Vault Assistant operations.

    This class manages Destiny 2 API interactions, manifest lookups, backup operations, and delegates
    session/authentication logic to BungieSessionManager. Integrates with Azure services for
    secure storage and scalable operations. It supports decoding and persisting Destiny 2 vault and character data
    using VaultModel and CharacterModel, and can persist decoded vaults to a relational database via ORM models.
    """

    def __init__(
        self,
        api_key: str = API_KEY,
        storage_conn_str: str = STORAGE_CONNECTION_STRING,
        table_name: str = TABLE_NAME,
        blob_container: str = BLOB_CONTAINER,
        api_base: str = BUNGIE_API_BASE,
        timeout: int = REQUEST_TIMEOUT
    ):
        """
        Initialize VaultAssistant with configuration and dependencies.

        Args:
            api_key (str): Bungie API key.
            storage_conn_str (str): Azure Storage connection string.
            table_name (str): Azure Table name for session storage.
            blob_container (str): Azure Blob container name.
            api_base (str): Bungie API base URL.
            timeout (int): Request timeout in seconds.
        """
        self.api_key = api_key
        self.storage_conn_str = storage_conn_str
        self.table_name = table_name
        self.blob_container = blob_container
        self.api_base = api_base
        self.timeout = timeout
        self.manifest_cache = ManifestCache.instance()
        self.session_manager = BungieSessionManager.instance()
        self.db_agent = None  # Ensure db_agent attribute always exists

    # Session/auth methods are now delegated to BungieSessionManager
    def exchange_code_for_token(self, code: str) -> dict:
        """
        Exchange OAuth code for access/refresh token, store in Table Storage, and return token data.

        Args:
            code (str): OAuth authorization code.

        Returns:
            dict: Token data from Bungie API.
        """
        return self.session_manager.exchange_code_for_token(code)

    def get_session(self) -> dict:
        """
        Retrieve stored session info including access token and membership ID.

        Returns:
            dict: Session info with access token and membership ID.
        """
        return self.session_manager.get_session()

    def refresh_token(self, refresh_token_val: str) -> tuple[dict, int]:
        """
        Refresh access token using the stored refresh token.

        Args:
            refresh_token_val (str): The refresh token value.

        Returns:
            tuple: (token_data, status_code)
        """
        return self.session_manager.refresh_token(refresh_token_val)

    def initialize_user(self) -> tuple[dict | None, int]:
        """
        Authenticate user, load manifest, and fetch Destiny 2 character summary using stored session.

        Returns:
            tuple: (user summary dict, status_code)
        """
        session = self.get_session()
        access_token = session["access_token"]
        membership_id = session["membership_id"]
        membership_type = session["membership_type"]
        if not all([membership_id, membership_type]):
            logging.error("No Destiny memberships found for user.")
            return None, 404
        # Ensure manifest is loaded using ManifestCache
        manifest_ready = self.manifest_cache.ensure_manifest()
        # Get character list
        headers = {
            "Authorization": f"Bearer {access_token}",
            "X-API-Key": self.api_key
        }
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
            race_def = self.manifest_cache.resolve_exact(race_hash, "DestinyRaceDefinition" )
            race_name = race_def.get("displayProperties", {}).get("name") if race_def else str(race_hash)
            character_summary[char_id] = {
                "classType": class_type,
                "className": class_name,
                "light": char["light"],
                "raceHash": race_hash,
                "raceName": race_name
            }
        logging.info("User initialized successfully: %s", membership_id)
        return {
            "message": "Assistant initialized.",
            "membershipId": membership_id,
            "membershipType": membership_type,
            "characters": character_summary,
            "manifestReady": manifest_ready
        }, 200

    def get_bungie_profile_last_modified(self, membership_id: str, membership_type: str, headers: dict) -> tuple[datetime | None, int]:
        """
        Helper to fetch Bungie profile last modified date as datetime.
        Args:
            membership_id (str): Destiny 2 membership ID.
            membership_type (str): Destiny 2 membership type.
            headers (dict): Headers to include in the request.

        Returns:
            (datetime or None, status_code)
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
            except Exception:
                bungie_last_modified_dt = None
        else:
            bungie_last_modified_dt = None
        return bungie_last_modified_dt, 200

    def process_query(self, query: dict) -> dict:
        """
        Process a query using the Vault Sentinel DB Agent.

        Args:
            query (dict): Query conforming to the Vault Sentinel schema.

        Returns:
            dict: Agent response.
        """
        if not hasattr(self, 'db_agent') or self.db_agent is None:
            raise AttributeError("VaultAssistant is missing a db_agent instance.")
        return self.db_agent.process_query(query)

    def get_vault(self) -> tuple[list, int] | tuple[None, int]:
        """
        Efficiently fetch user's Destiny 2 vault inventory, using blob cache if up-to-date.

        Compares the blob's last modified date with Bungie profile's lastModified before fetching inventory.

        Returns:
            tuple: (inventory list, status_code)
        """
        session = self.get_session()
        access_token = session["access_token"]
        membership_id = session["membership_id"]
        membership_type = session["membership_type"]
        if not all([membership_id, membership_type]):
            logging.error("No Destiny memberships found for user.")
            return None, 404

        headers = {
            "Authorization": f"Bearer {access_token}",
            "X-API-Key": self.api_key
        }
        # Get Bungie profile lastModified using helper
        bungie_last_modified_dt, status = self.get_bungie_profile_last_modified(membership_id, membership_type, headers)
        if status != 200:
            return None, status

        # Get blob last modified using helpers
        blob_name = f"{membership_id}.json"
        blob_exists_flag = blob_exists(self.storage_conn_str, self.blob_container, blob_name)
        blob_last_modified_dt = get_blob_last_modified(self.storage_conn_str, self.blob_container, blob_name)

        # If blob exists and is newer than Bungie profile, use cached inventory
        if blob_exists_flag and bungie_last_modified_dt and blob_last_modified_dt and blob_last_modified_dt >= bungie_last_modified_dt:
            logging.info(
                "Using cached vault inventory from blob for user: %s", membership_id)
            blob_data = load_blob(self.storage_conn_str, self.blob_container, blob_name)
            inventory = json.loads(blob_data)
            return inventory, 200

        # Otherwise, fetch fresh inventory and update blob
        inventory_url = f"{self.api_base}/Destiny2/{membership_type}/Profile/{membership_id}/?components=102"
        inv_resp = retry_request(
            requests.get, inventory_url, headers=headers, timeout=self.timeout)
        if not inv_resp.ok:
            logging.error(
                "Failed to get vault inventory: status %d", inv_resp.status_code)
            return None, inv_resp.status_code
        inventory = inv_resp.json()["Response"]["profileInventory"]["data"]["items"]
        save_blob(self.storage_conn_str, self.blob_container,
                  blob_name, json.dumps(inventory))
        logging.info("Vault inventory fetched and saved for user: %s", membership_id)
        return inventory, 200

    def get_characters(self) -> tuple[dict, int] | tuple[None, int]:
        """
        Fetch user's Destiny 2 character inventories and save to blob storage, using cached data if up-to-date.

        Returns:
            tuple: (inventories dict, status_code)
        """
        session = self.get_session()
        access_token = session["access_token"]
        headers = {
            "Authorization": f"Bearer {access_token}",
            "X-API-Key": self.api_key
        }
        membership_id = session["membership_id"]
        membership_type = session["membership_type"]
        if not all([membership_id, membership_type]):
            logging.error("No Destiny memberships found for user.")
            return None, 404

        # Get Bungie profile lastModified using helper
        bungie_last_modified_dt, status = self.get_bungie_profile_last_modified(membership_id, membership_type, headers)
        if status != 200:
            return None, status

        # Get blob last modified using helpers
        blob_name = f"{membership_id}-characters.json"
        blob_exists_flag = blob_exists(self.storage_conn_str, self.blob_container, blob_name)
        blob_last_modified_dt = get_blob_last_modified(self.storage_conn_str, self.blob_container, blob_name)

        # If blob exists and is newer than Bungie profile, use cached inventory
        if blob_exists_flag and bungie_last_modified_dt and blob_last_modified_dt and blob_last_modified_dt >= bungie_last_modified_dt:
            logging.info("Using cached character inventories from blob for user: %s", membership_id)
            blob_data = load_blob(self.storage_conn_str, self.blob_container, blob_name)
            inventory_data = json.loads(blob_data)
            return inventory_data, 200

        # Otherwise, fetch fresh character summary and inventory, then enrich
        char_url = f"{self.api_base}/Destiny2/{membership_type}/Profile/{membership_id}/?components=200,201,900"
        char_resp = retry_request(
            requests.get, char_url, headers=headers, timeout=self.timeout)
        if not char_resp.ok:
            logging.error("Failed to get character data: status %d", char_resp.status_code)
            return None, char_resp.status_code
        resp_json = char_resp.json()["Response"]
        char_data = resp_json["characters"]["data"]
        inventory_data = resp_json["characterInventories"]["data"]

        # Extract seasonal artifact info from profileProgression
        profile_prog = resp_json.get("profileProgression", {}).get("data", {}) or {}
        seasonal_artifact = profile_prog.get("seasonalArtifact", {}) or {}
        artifact_hash = seasonal_artifact.get("artifactItemHash")
        artifact_power_bonus = seasonal_artifact.get("powerBonus")

        # Enrich each character with manifest lookups
        enriched = {}
        for char_id, char_info in char_data.items():
            race_hash = char_info.get("raceHash")
            class_hash = char_info.get("classHash")
            gender_hash = char_info.get("genderHash")
            # Manifest lookups
            race_def = self.manifest_cache.resolve_exact(race_hash, "DestinyRaceDefinition") if race_hash else None
            class_def = self.manifest_cache.resolve_exact(class_hash, "DestinyClassDefinition") if class_hash else None
            gender_def = self.manifest_cache.resolve_exact(gender_hash, "DestinyGenderDefinition") if gender_hash else None
            enriched[char_id] = {
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
            # Attach seasonal artifact (profile-wide) to each character record for convenience
            if artifact_hash is not None:
                enriched[char_id]["artifact"] = {
                    "itemHash": artifact_hash,
                    "powerBonus": artifact_power_bonus,
                }

        # Save enriched character data to blob
        save_blob(self.storage_conn_str, self.blob_container, blob_name, json.dumps(enriched))
        logging.info("Character inventories (enriched) fetched and saved for user: %s", membership_id)
        return enriched, 200

    def get_manifest_item(self, item_hash: str | int, definition_type: str = None) -> tuple[dict, int]:
        """
        Resolve a Destiny 2 item hash against manifest definitions.

        Args:
            item_hash (str | int): Item hash to resolve (string or integer).
            definition_type (str, optional): Manifest definition type to search in. If None, all loaded types are searched.

        Returns:
            tuple: (definition dict, status_code)
        """
        if definition_type:
            definition = self.manifest_cache.resolve_exact(item_hash, definition_type)
            if definition:
                return definition, 200
            return None, 404
        # If no type specified, search all required types
        for def_type in BUNGIE_REQUIRED_DEFS:
            definition = self.manifest_cache.resolve_exact(item_hash, def_type)
            if definition:
                return definition, 200
        return None, 404

    def save_dim_backup(self, membership_id: str, dim_json_str: str) -> tuple[dict, int]:
        """
        Save a DIM backup and its metadata.

        Args:
            membership_id (str): Destiny 2 membership ID.
            dim_json_str (str): DIM backup JSON string.

        Returns:
            tuple: (result dict, status_code)
        """
        logging.info("Saving DIM backup for user: %s", membership_id)
        timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
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
            tuple: (backups dict, status_code)
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

    def decode_vault(self, include_perks: bool = False, limit: int = None, offset: int = 0) -> tuple[list, int]:
        """
        Decode the vault inventory using VaultModel.from_components for each item. Optionally include perks. Supports pagination.

        This method loads the user's vault inventory from blob storage, decodes it using VaultModel,
        and returns a list of enriched item dicts. If requested, perks are included. Supports offset/limit for pagination.
        The decoded vault can be persisted to a database using the ORM Vault and Item models.

        Args:
            include_perks (bool): If True, include perks for each item.
            limit (int): Max number of items to return.
            offset (int): Number of items to skip.

        Returns:
            tuple: (decoded items list, status_code)
        """
        session = self.get_session()
        membership_id = session["membership_id"]
        membership_type = session["membership_type"]
        headers = {
            "Authorization": f"Bearer {session['access_token']}",
            "X-API-Key": self.api_key
            }

        decoded_blob_name = f"{membership_id}-vault-decoded.json"
        date_last_played = self.get_bungie_profile_last_modified(membership_id, membership_type, headers)[0]
        if date_last_played:
            blob_data = load_blob_if_stale(self.storage_conn_str, self.blob_container, decoded_blob_name, date_last_played)
            if blob_data:
                logging.info("Using cached decoded vault from blob for user: %s", membership_id)
                decoded_items = json.loads(blob_data)
                paged_items = decoded_items[offset:offset + limit] if limit is not None else decoded_items[offset:]
                return paged_items, 200

        logging.info("Decoding vault inventory for user: %s", membership_id)
        blob_name = f"{membership_id}.json"
        blob_data = load_blob(self.storage_conn_str, self.blob_container, blob_name)
        if blob_data is None:
            logging.error("Vault blob not found for user: %s", membership_id)
            return [], 404
        items = json.loads(blob_data)
        paged_items = items[offset:offset + limit] if limit is not None else items[offset:]
        # Use VaultModel.from_components to decode and enrich inventory
        vault_model = VaultModel.from_components(paged_items, {})
        decoded_items = []
        for item in vault_model.items:
            decoded = item.model_dump()
            if include_perks and hasattr(item, "perks"):
                decoded["perks"] = item.perks
            decoded_items.append(decoded)

        if limit is None and offset == 0:
            # Only save if we are returning the full set or a positive slice from the start
            # (to avoid saving partial slices)
            save_blob(self.storage_conn_str, self.blob_container,
                    decoded_blob_name, json.dumps(decoded_items))
        return decoded_items, 200
    def decode_characters(self, include_perks: bool = False, limit: int = None, offset: int = 0) -> tuple[list, int]:
        """
        Decode the character equipment using CharacterModel.from_components for each character. Optionally include perks. Supports pagination.

        This method loads the user's character inventories from blob storage, decodes each character using CharacterModel,
        and returns a list of enriched character dicts. Each character's items are paginated and optionally include perks.
        Decoded character inventories can be persisted to a database using the ORM Character and Item models.

        Args:
            include_perks (bool): If True, include perks for each item.
            limit (int): Max number of items to return per character.
            offset (int): Number of items to skip per character.

        Returns:
            tuple: (decoded items list, status_code)
        """
        session = self.get_session()
        membership_id = session["membership_id"]
        membership_type = session["membership_type"]
        headers = {
            "Authorization": f"Bearer {session['access_token']}",
            "X-API-Key": self.api_key
            }

        decoded_blob_name = f"{membership_id}-characters-decoded.json"
        date_last_played = self.get_bungie_profile_last_modified(membership_id, membership_type, headers)[0]
        if date_last_played:
            blob_data = load_blob_if_stale(self.storage_conn_str, self.blob_container, decoded_blob_name, date_last_played)
            if blob_data is not None:
                logging.info("Using cached decoded characters from blob for user: %s", membership_id)
                decoded_characters = json.loads(blob_data)
                return decoded_characters, 200

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

        decoded_characters: list[dict] = []
        for char_id, char_data in raw.items():
            char_items = char_data.get("items", [])
            paged_items = char_items[offset:offset + limit] if limit is not None else char_items[offset:]
            char_data_no_items = {k: v for k, v in char_data.items() if k != "items"}
            artifact_raw = char_data.get("artifact") if isinstance(char_data.get("artifact"), dict) else None
            char_model = CharacterModel.from_components(char_data_no_items, paged_items, {}, artifact_raw=artifact_raw)
            char_dict = char_model.model_dump()
            cleaned_items: list[dict] = []
            for it in char_model.items:
                it_dict = it.model_dump()
                if not include_perks and "perks" in it_dict:
                    it_dict.pop("perks", None)
                cleaned_items.append(it_dict)
            char_dict["items"] = cleaned_items
            decoded_characters.append(char_dict)

        if limit is None and offset == 0:
            save_blob(self.storage_conn_str, self.blob_container, decoded_blob_name, json.dumps(decoded_characters))
        return decoded_characters, 200

    def get_session_token(self) -> tuple[dict, int]:
        """
        Return current access token and membership ID, wrapped for external use.

        Returns:
            tuple: (session dict, status_code)
        """
        session = self.get_session()
        return {
            "access_token": session["access_token"],
            "membership_id": session["membership_id"]
        }, 200

    def save_object(self, mime_object) -> tuple[dict, int]:
        """
        Save a MIME object (file-like) to Azure Blob Storage using save_blob helper.

        The MIME object should have 'filename', 'content_type', and 'content' attributes.
        Returns a dict with blob name and URL on success.

        Args:
            mime_object: Object with filename, content_type, and content attributes.

        Returns:
            tuple: (result dict, status_code)
        """
        logging.info("Saving MIME object to blob storage.")
        filename = getattr(mime_object, 'filename', None)
        content_type = getattr(mime_object, 'content_type', None)
        content = getattr(mime_object, 'content', None)
        if not filename or not content:
            logging.error("MIME object missing filename or content.")
            return {"error": "Missing filename or content in MIME object."}, 400
        try:
            # Use save_blob helper with content_type
            save_blob(self.storage_conn_str, self.blob_container, filename, content, content_type=content_type)
            container_url = BlobServiceClient.from_connection_string(self.storage_conn_str).get_container_client(self.blob_container).url
            blob_url = f"{container_url}/{filename}"
            logging.info("Saved MIME object as blob: %s", blob_url)
            return {"message": "Object saved successfully.", "blob": filename, "url": blob_url}, 200
        except Exception as e:
            logging.error("Failed to save MIME object: %s", e)
            return {"error": f"Failed to save object: {e}"}, 500

    def get_item_full_info(self, item_hash: str, item_instance_id: str = None) -> tuple[dict | None, int]:
        """
        Retrieve full information for an item, including perks, stats, and other properties.
        If item_instance_id is provided, fetch instance-specific data (e.g., rolled perks, stats).

        Args:
            item_hash (str): Destiny 2 item hash.
            item_instance_id (str, optional): Destiny 2 item instance ID.

        Returns:
            tuple: (item info dict, status_code)
        """
        raw_data = {
            "itemHash": item_hash,
            "itemInstanceId": item_instance_id
        }
        item_model = ItemModel.from_raw_data(raw_data, self.session_manager, self.manifest_cache, item_instance_id)
        if item_model.itemName == "Unknown":
            logging.error("Item hash %s not found in manifest.", item_hash)
            return None, 404
        return item_model.model_dump(), 200
