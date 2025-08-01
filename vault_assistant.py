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
from helpers import (
    get_manifest,
    retry_request,
    save_blob,
    save_dim_backup_blob,
    resolve_manifest_hash,
    normalize_item_hash
)
from bungie_session_manager import BungieSessionManager

class VaultAssistant:
    """
    Business logic for Destiny 2 Vault Assistant operations.

    This class manages Destiny 2 API interactions, manifest lookups, backup operations,
    and delegates session/authentication logic to BungieSessionManager.
    """

    def __init__(self, api_key: str, storage_conn_str: str, table_name: str, blob_container: str, manifest_cache: dict, api_base: str, timeout: int):
        """
        Initialize VaultAssistant with configuration and dependencies.

        Args:
            api_key (str): Bungie API key.
            storage_conn_str (str): Azure Storage connection string.
            table_name (str): Azure Table name for session storage.
            blob_container (str): Azure Blob container name.
            manifest_cache (dict): Manifest cache for Destiny 2 definitions.
            api_base (str): Bungie API base URL.
            timeout (int): Request timeout in seconds.
        """
        self.api_key = api_key
        self.storage_conn_str = storage_conn_str
        self.table_name = table_name
        self.blob_container = blob_container
        if 'definitions' not in manifest_cache:
            manifest_cache['definitions'] = {}
        self.manifest_cache = manifest_cache
        self.api_base = api_base
        self.timeout = timeout
        # Use BungieSessionManager for all session/auth logic
        self.session_manager = BungieSessionManager(
            api_key=api_key,
            storage_conn_str=storage_conn_str,
            table_name=table_name,
            api_base=api_base,
            timeout=timeout
        )

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
        headers = {
            "Authorization": f"Bearer {access_token}",
            "X-API-Key": self.api_key
        }
        profile_url = f"{self.api_base}/User/GetMembershipsForCurrentUser/"
        logging.info("Initializing user with access token.")
        profile_resp = retry_request(
            requests.get, profile_url, headers=headers, timeout=self.timeout)
        if not profile_resp.ok:
            logging.error("Failed to get membership: status %d",
                          profile_resp.status_code)
            return None, profile_resp.status_code
        profile_data = profile_resp.json()["Response"]
        if not profile_data.get("destinyMemberships"):
            logging.error("No Destiny memberships found for user.")
            return None, 404
        membership = profile_data["destinyMemberships"][0]
        membership_id = membership["membershipId"]
        membership_type = membership["membershipType"]
        # Confirm manifest is loaded
        get_manifest(headers, self.manifest_cache,
                     self.api_base, retry_request, self.timeout)
        # Get character list
        characters_url = f"{self.api_base}/Destiny2/{membership_type}/Profile/{membership_id}/?components=200"
        char_resp = retry_request(
            requests.get, characters_url, headers=headers, timeout=self.timeout)
        if not char_resp.ok:
            logging.error("Failed to get characters: status %d",
                          char_resp.status_code)
            return None, char_resp.status_code
        characters_data = char_resp.json()["Response"]["characters"]["data"]
        character_summary = {
            char_id: {
                "classType": char["classType"],
                "light": char["light"],
                "raceHash": char["raceHash"]
            } for char_id, char in characters_data.items()
        }
        logging.info("User initialized successfully: %s", membership_id)
        return {
            "message": "Assistant initialized.",
            "membershipId": membership_id,
            "membershipType": membership_type,
            "characters": character_summary,
            "manifestReady": True
        }, 200

    def get_vault(self) -> tuple[list, int] | tuple[None, int]:
        """
        Fetch user's Destiny 2 vault inventory and save to blob storage using stored session.

        Returns:
            tuple: (inventory list, status_code)
        """
        session = self.get_session()
        access_token = session["access_token"]
        headers = {
            "Authorization": f"Bearer {access_token}",
            "X-API-Key": self.api_key
        }
        profile_url = f"{self.api_base}/User/GetMembershipsForCurrentUser/"
        logging.info("Fetching vault for user.")
        profile_resp = retry_request(
            requests.get, profile_url, headers=headers, timeout=self.timeout)
        if not profile_resp.ok:
            logging.error("Failed to get membership: status %d",
                          profile_resp.status_code)
            return None, profile_resp.status_code
        profile_data = profile_resp.json()["Response"]
        membership = profile_data["destinyMemberships"][0]
        membership_id = membership["membershipId"]
        membership_type = membership["membershipType"]
        inventory_url = f"{self.api_base}/Destiny2/{membership_type}/Profile/{membership_id}/?components=102"
        inv_resp = retry_request(
            requests.get, inventory_url, headers=headers, timeout=self.timeout)
        if not inv_resp.ok:
            logging.error(
                "Failed to get vault inventory: status %d", inv_resp.status_code)
            return None, inv_resp.status_code
        inventory = inv_resp.json(
        )["Response"]["profileInventory"]["data"]["items"]
        save_blob(self.storage_conn_str, self.blob_container,
                  f"{membership_id}.json", json.dumps(inventory))
        logging.info(
            "Vault inventory fetched and saved for user: %s", membership_id)
        return inventory, 200

    def get_characters(self) -> tuple[dict, int] | tuple[None, int]:
        """
        Fetch user's Destiny 2 character equipment and save to blob storage using stored session.

        Returns:
            tuple: (equipment dict, status_code)
        """
        session = self.get_session()
        access_token = session["access_token"]
        headers = {
            "Authorization": f"Bearer {access_token}",
            "X-API-Key": self.api_key
        }
        profile_url = f"{self.api_base}/User/GetMembershipsForCurrentUser/"
        logging.info("Fetching character equipment for user.")
        profile_resp = retry_request(
            requests.get, profile_url, headers=headers, timeout=self.timeout)
        if not profile_resp.ok:
            logging.error("Failed to get membership: status %d",
                          profile_resp.status_code)
            return None, profile_resp.status_code
        profile_data = profile_resp.json()["Response"]
        membership = profile_data["destinyMemberships"][0]
        membership_id = membership["membershipId"]
        membership_type = membership["membershipType"]
        char_url = f"{self.api_base}/Destiny2/{membership_type}/Profile/{membership_id}/?components=205"
        char_resp = retry_request(
            requests.get, char_url, headers=headers, timeout=self.timeout)
        if not char_resp.ok:
            logging.error(
                "Failed to get character equipment: status %d", char_resp.status_code)
            return None, char_resp.status_code
        equipment = char_resp.json()["Response"]["characterEquipment"]["data"]
        save_blob(self.storage_conn_str, self.blob_container,
                  f"{membership_id}-characters.json", json.dumps(equipment))
        logging.info(
            "Character equipment fetched and saved for user: %s", membership_id)
        return equipment, 200

    def get_manifest_item(self, item_hash, definition=None) -> tuple[dict, int]:
        """
        Resolve a Destiny 2 item hash against manifest definitions.

        Args:
            item_hash: Item hash to resolve.
            definition: Optional manifest definition type.
        Returns:
            tuple: (definition dict, status_code)
        """
        norm_hash = normalize_item_hash(item_hash)
        definition, def_type = resolve_manifest_hash(norm_hash, self.manifest_cache.get("definitions", {}))
        if not definition:
            # Try fallback: sometimes hashes are passed as signed ints in string form
            try:
                alt_hash = normalize_item_hash(int(norm_hash))
                if alt_hash != norm_hash:
                    definition, def_type = resolve_manifest_hash(alt_hash, self.manifest_cache.get("definitions", {}))
            except Exception:
                pass
        if not definition:
            return {"error": "Item not found"}, 404
        return definition, 200

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

    # ...existing code...

    def decode_vault(self, include_perks: bool = False, limit: int = None, offset: int = 0) -> tuple[list, int]:
        """
        Decode the vault inventory using manifest definitions. Optionally include perks. Supports pagination.

        Args:
            include_perks (bool): If True, include perks for each item.
            limit (int): Max number of items to return.
            offset (int): Number of items to skip.
        Returns:
            tuple: (decoded items list, status_code)
        """
        return self._decode_blob(source="vault", include_perks=include_perks, limit=limit, offset=offset), 200

    def decode_characters(self, include_perks: bool = False, limit: int = None, offset: int = 0) -> tuple[list, int]:
        """
        Decode the character equipment using manifest definitions. Optionally include perks. Supports pagination.

        Args:
            include_perks (bool): If True, include perks for each item.
            limit (int): Max number of items to return per character.
            offset (int): Number of items to skip per character.
        Returns:
            tuple: (decoded items list, status_code)
        """
        return self._decode_blob(source="characters", include_perks=include_perks, limit=limit, offset=offset), 200

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

    def _get_blob_container(self) -> BlobServiceClient:
        """
        Return the blob container client for the main blob container.

        Returns:
            BlobServiceClient: The blob container client.
        """
        return BlobServiceClient.from_connection_string(self.storage_conn_str).get_container_client(self.blob_container)

    def _get_manifest_definitions(self) -> dict:
        """
        Fetch and return manifest definitions, using cache if available.

        Returns:
            dict: Manifest definitions.
        """
        headers = {"X-API-Key": self.api_key}
        return get_manifest(headers, self.manifest_cache, self.api_base, retry_request, self.timeout)

    def _decode_blob(self, source: str = 'vault', include_perks: bool = False, limit: int = None, offset: int = 0) -> list:
        """
        Decode and enrich inventory or character data using manifest definitions. Supports pagination.

        Args:
            source (str): 'vault' or 'characters'.
            include_perks (bool): If True, include perks for each item.
            limit (int): Max number of items to return.
            offset (int): Number of items to skip.
        Returns:
            list: Decoded items.
        """
        logging.info("Starting decode pass for source: %s", source)
        session = self.get_session()
        membership_id = session["membership_id"]
        blob_name = f"{membership_id}.json" if source == "vault" else f"{membership_id}-characters.json"
        container = self._get_blob_container()
        blob_data = container.download_blob(blob_name).readall()
        items = json.loads(blob_data)
        manifest = self._get_manifest_definitions()
        definitions = manifest["definitions"] if isinstance(manifest, dict) and "definitions" in manifest else manifest
        decoded_items = []
        if isinstance(items, list):  # Vault
            # Apply offset and limit for pagination
            paged_items = items[offset:offset+limit] if limit is not None else items[offset:]
            for item in paged_items:
                item_hash = normalize_item_hash(item.get("itemHash"))
                defn, _ = resolve_manifest_hash(item_hash, definitions)
                if defn is None:
                    logging.warning("Item hash %s not found in manifest definitions.", item_hash)
                    decoded = {
                        "name": "Unknown",
                        "type": "Unknown",
                        "itemHash": item.get("itemHash"),
                        "itemInstanceId": item.get("itemInstanceId"),
                        "manifestMissing": True
                    }
                else:
                    decoded = {
                        "name": defn.get("displayProperties", {}).get("name", "Unknown"),
                        "type": defn.get("itemTypeDisplayName", "Unknown"),
                        "itemHash": item.get("itemHash"),
                        "itemInstanceId": item.get("itemInstanceId"),
                    }
                    if include_perks:
                        decoded["perks"] = self._extract_perks(defn, definitions)
                decoded_items.append(decoded)
        elif isinstance(items, dict):  # Characters
            for char_id, char_data in items.items():
                char_items = char_data.get("items", [])
                # Apply offset and limit for pagination per character
                paged_char_items = char_items[offset:offset+limit] if limit is not None else char_items[offset:]
                enriched_items = []
                for item in paged_char_items:
                    item_hash = normalize_item_hash(item.get("itemHash"))
                    defn, _ = resolve_manifest_hash(item_hash, definitions)
                    if defn is None:
                        logging.warning("Item hash %s not found in manifest definitions.", item_hash)
                        decoded = {
                            "name": "Unknown",
                            "type": "Unknown",
                            "itemHash": item.get("itemHash"),
                            "itemInstanceId": item.get("itemInstanceId"),
                            "manifestMissing": True
                        }
                    else:
                        decoded = {
                            "name": defn.get("displayProperties", {}).get("name", "Unknown"),
                            "type": defn.get("itemTypeDisplayName", "Unknown"),
                            "itemHash": item.get("itemHash"),
                            "itemInstanceId": item.get("itemInstanceId"),
                        }
                        if include_perks:
                            decoded["perks"] = self._extract_perks(defn, definitions)
                    enriched_items.append(decoded)
                decoded_items.append({
                    "characterId": char_id,
                    "items": enriched_items
                })
        logging.info("Decode pass complete for source: %s", source)
        return decoded_items

    def _extract_perks(self, defn, definitions):
        """
        Extract perks from an item definition.

        Args:
            defn (dict): Item manifest definition.
            definitions (dict): Manifest definitions cache.
        Returns:
            list: List of perks dicts.
        """
        perks = []
        for socket in defn.get("sockets", {}).get("socketEntries", []):
            plug_hash = socket.get("singleInitialItemHash")
            if plug_hash:
                norm_plug_hash = normalize_item_hash(plug_hash)
                plug_def, _ = resolve_manifest_hash(norm_plug_hash, definitions)
                if plug_def:
                    perks.append({
                        "name": plug_def.get("displayProperties", {}).get("name", "Unknown"),
                        "description": plug_def.get("displayProperties", {}).get("description", ""),
                        "icon": plug_def.get("displayProperties", {}).get("icon", None),
                        "plugItemHash": plug_hash
                    })
        return perks

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
            save_blob(self.storage_conn_str,
                      self.blob_container, filename, content)
            container_url = BlobServiceClient.from_connection_string(
                self.storage_conn_str).get_container_client(self.blob_container).url
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
        definitions = self._get_manifest_definitions()
        norm_hash = normalize_item_hash(item_hash)
        item_def = definitions.get(norm_hash)
        if not item_def:
            logging.error("Item hash %s not found in manifest.", norm_hash)
            return None, 404
        item_info = self._build_item_base_info(item_def, norm_hash, definitions)
        if item_instance_id:
            instance_info = self._build_item_instance_info(item_instance_id, definitions)
            if instance_info:
                item_info.update(instance_info)
        return item_info, 200

    def _build_item_base_info(self, item_def, item_hash, definitions):
        """
        Build base information for a Destiny 2 item using its manifest definition.
        Includes display properties, type, tier, inventory info, masterwork/mods, stats, and perks.

        Args:
            item_def (dict): The manifest definition for the item.
            item_hash (str|int): The normalized item hash.
            definitions (dict): The manifest definitions cache.
        Returns:
            dict: Dictionary of item base information.
        """
        info = {
            "name": item_def.get("displayProperties", {}).get("name", "Unknown"),
            "description": item_def.get("displayProperties", {}).get("description", ""),
            "type": item_def.get("itemTypeDisplayName", "Unknown"),
            "icon": item_def.get("displayProperties", {}).get("icon", None),
            "tier": item_def.get("inventory", {}).get("tierTypeName", "Unknown"),
            "itemHash": item_hash,
            "itemType": item_def.get("itemType"),
            "itemSubType": item_def.get("itemSubType"),
            "itemCategoryHashes": item_def.get("itemCategoryHashes", []),
            "itemTypeDisplayName": item_def.get("itemTypeDisplayName"),
            "itemTypeAndTierDisplayName": item_def.get("itemTypeAndTierDisplayName"),
            "sourceString": item_def.get("sourceString"),
            "collectibleHash": item_def.get("collectibleHash"),
        }

        # Inventory/Stack Info
        inventory = item_def.get("inventory", {})
        info["maxStackSize"] = inventory.get("maxStackSize")
        info["stackUniqueLabel"] = inventory.get("stackUniqueLabel")
        info["transferStatus"] = inventory.get("transferStatus")
        info["expirationTooltip"] = inventory.get("expirationTooltip")
        info["isInstanceItem"] = inventory.get("isInstanceItem")
        info["nonTransferrable"] = inventory.get("nonTransferrable")

        # Masterwork/Mod Info (from sockets)
        masterwork_info = None
        mod_info = []
        sockets_def = item_def.get("sockets", {}).get("socketEntries", [])
        for socket in sockets_def:
            plug_hash = socket.get("singleInitialItemHash")
            if plug_hash:
                plug_def, _ = resolve_manifest_hash(str(plug_hash), definitions)
                # Check for masterwork
                if plug_def and plug_def.get("itemTypeDisplayName", "").lower().find("masterwork") != -1:
                    masterwork_info = {
                        "name": plug_def.get("displayProperties", {}).get("name", "Unknown"),
                        "description": plug_def.get("displayProperties", {}).get("description", ""),
                        "icon": plug_def.get("displayProperties", {}).get("icon", None),
                        "plugItemHash": plug_hash
                    }
                # Check for mods
                if plug_def and plug_def.get("itemTypeDisplayName", "").lower().find("mod") != -1:
                    mod_info.append({
                        "name": plug_def.get("displayProperties", {}).get("name", "Unknown"),
                        "description": plug_def.get("displayProperties", {}).get("description", ""),
                        "icon": plug_def.get("displayProperties", {}).get("icon", None),
                        "plugItemHash": plug_hash
                    })
        if masterwork_info:
            info["masterwork"] = masterwork_info
        if mod_info:
            info["mods"] = mod_info
        
        # Seasonal/Power Cap
        info["powerCapHash"] = item_def.get("quality", {}).get("powerCapHash")
        info["seasonHash"] = item_def.get("seasonHash")
        info["seasonalContent"] = item_def.get("seasonalContent")
        info["quality"] = item_def.get("quality")
        
        # Stats
        stats = {}
        stats_def = item_def.get("stats", {}).get("stats", {})
        for stat_hash, stat_obj in stats_def.items():
            stat_def, _ = resolve_manifest_hash(stat_hash, definitions)
            stat_name = stat_def.get("displayProperties", {}).get("name", stat_hash) if stat_def else stat_hash
            stats[stat_name] = stat_obj.get("value")
        if stats:
            info["stats"] = stats
        
        # Perks (sockets)
        sockets = []
        socket_categories = item_def.get("sockets", {}).get("socketEntries", [])
        for socket in socket_categories:
            plug_hash = socket.get("singleInitialItemHash")
            if plug_hash:
                plug_def, _ = resolve_manifest_hash(str(plug_hash), definitions)
                if plug_def:
                    sockets.append({
                        "name": plug_def.get("displayProperties", {}).get("name", "Unknown"),
                        "description": plug_def.get("displayProperties", {}).get("description", ""),
                        "icon": plug_def.get("displayProperties", {}).get("icon", None),
                        "plugItemHash": plug_hash
                    })
        if sockets:
            info["perks"] = sockets
        
        return info

    def _build_item_instance_info(self, item_instance_id, definitions):
        """
        Build instance-specific information for a Destiny 2 item, such as rolled perks, stats, masterwork, and mods.
        Fetches instance data from the Bungie API using the item_instance_id.

        Args:
            item_instance_id (str): The Destiny 2 item instance ID.
            definitions (dict): The manifest definitions cache.
        Returns:
            dict | None: Dictionary of instance-specific item info, or None if not found.
        """
        session = self.get_session()
        access_token = session["access_token"]
        membership_id = session["membership_id"]
        headers_auth = {
            "Authorization": f"Bearer {access_token}",
            "X-API-Key": self.api_key
        }
        # Try to get membership type
        profile_url = f"{self.api_base}/User/GetMembershipsForCurrentUser/"
        profile_resp = retry_request(
            requests.get, profile_url, headers=headers_auth, timeout=self.timeout)
        if not profile_resp.ok:
            return None
        profile_data = profile_resp.json().get("Response", {})
        if not profile_data.get("destinyMemberships"):
            return None
        membership_type = profile_data["destinyMemberships"][0].get("membershipType", "1")
        # Fetch item instance data
        instance_url = f"{self.api_base}/Destiny2/{membership_type}/Profile/{membership_id}/Item/{item_instance_id}/?components=300,302,304"
        instance_resp = retry_request(
            requests.get, instance_url, headers=headers_auth, timeout=self.timeout)
        if not instance_resp.ok:
            return None
        instance_data = instance_resp.json().get("Response", {})
        info = {}
        # Instance stats
        inst_stats = instance_data.get("itemStats", {}).get("stats", {})
        if inst_stats:
            stats_instance = {}
            for stat_hash, stat_obj in inst_stats.items():
                stat_def, _ = resolve_manifest_hash(str(stat_hash), definitions)
                stat_name = stat_def.get("displayProperties", {}).get("name", stat_hash) if stat_def else stat_hash
                stats_instance[stat_name] = stat_obj.get("value")
            info["instanceStats"] = stats_instance
        # Instance perks (sockets), masterwork, mods
        inst_sockets = instance_data.get("sockets", {}).get("sockets", [])
        perks_instance = []
        masterwork_instance = None
        mods_instance = []
        for socket in inst_sockets:
            plug_hash = socket.get("plugHash")
            if plug_hash:
                plug_def, _ = resolve_manifest_hash(str(plug_hash), definitions)
                if plug_def:
                    display_name = plug_def.get("itemTypeDisplayName", "").lower()
                    # Perks
                    perks_instance.append({
                        "name": plug_def.get("displayProperties", {}).get("name", "Unknown"),
                        "description": plug_def.get("displayProperties", {}).get("description", ""),
                        "icon": plug_def.get("displayProperties", {}).get("icon", None),
                        "plugItemHash": plug_hash
                    })
                    # Masterwork
                    if "masterwork" in display_name:
                        masterwork_instance = {
                            "name": plug_def.get("displayProperties", {}).get("name", "Unknown"),
                            "description": plug_def.get("displayProperties", {}).get("description", ""),
                            "icon": plug_def.get("displayProperties", {}).get("icon", None),
                            "plugItemHash": plug_hash
                        }
                    # Mods
                    if "mod" in display_name:
                        mods_instance.append({
                            "name": plug_def.get("displayProperties", {}).get("name", "Unknown"),
                            "description": plug_def.get("displayProperties", {}).get("description", ""),
                            "icon": plug_def.get("displayProperties", {}).get("icon", None),
                            "plugItemHash": plug_hash
                        })
        if perks_instance:
            info["instancePerks"] = perks_instance
        if masterwork_instance:
            info["instanceMasterwork"] = masterwork_instance
        if mods_instance:
            info["instanceMods"] = mods_instance
        return info
