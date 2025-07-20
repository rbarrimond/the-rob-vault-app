from datetime import datetime
from azure.storage.blob import BlobServiceClient
from azure.data.tables import TableServiceClient
import os
import json
import logging
import requests
from helpers import (get_manifest, retry_request,
                     save_blob, save_dim_backup_blob)


class VaultAssistant:
    """Business logic for Destiny 2 Vault Assistant operations."""

    def __init__(self, api_key, storage_conn_str, table_name, blob_container, manifest_cache, api_base, timeout):
        """Initialize VaultAssistant with configuration and dependencies."""
        self.api_key = api_key
        self.storage_conn_str = storage_conn_str
        self.table_name = table_name
        self.blob_container = blob_container
        self.manifest_cache = manifest_cache
        self.api_base = api_base
        self.timeout = timeout
        self._token_expiry_margin = 60  # seconds before expiry to refresh

    def _get_token_entity(self):
        table_service = TableServiceClient.from_connection_string(self.storage_conn_str)
        table_client = table_service.get_table_client(self.table_name)
        try:
            entity = table_client.get_entity(partition_key="AuthSession", row_key="last")
            return entity
        except Exception:
            return None

    def _is_token_expired(self):
        entity = self._get_token_entity()
        if not entity:
            return True
        expires_in = int(entity.get("ExpiresIn", "3600"))
        # Assume we store the time when token was issued
        issued_at = entity.get("IssuedAt")
        if not issued_at:
            return True
        issued_at_dt = datetime.strptime(issued_at, "%Y-%m-%dT%H:%M:%S")
        now = datetime.utcnow()
        elapsed = (now - issued_at_dt).total_seconds()
        # Refresh if within margin of expiry
        return elapsed > (expires_in - self._token_expiry_margin)

    def _ensure_token_valid(self):
        entity = self._get_token_entity()
        if not entity:
            return None
        if self._is_token_expired():
            refresh_token_val = entity.get("RefreshToken")
            if refresh_token_val:
                token_data, _ = self.refresh_token(refresh_token_val)
                # Update entity with new token info
                entity.update({
                    "AccessToken": token_data.get("access_token", ""),
                    "RefreshToken": token_data.get("refresh_token", ""),
                    "ExpiresIn": str(token_data.get("expires_in", "3600")),
                    "IssuedAt": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")
                })
                table_service = TableServiceClient.from_connection_string(self.storage_conn_str)
                table_client = table_service.get_table_client(self.table_name)
                table_client.upsert_entity(entity=entity)
        return entity
    
    def exchange_code_for_token(self, code: str) -> dict:
        """Exchange OAuth code for access/refresh token, store in Table Storage, and return token data."""
        token_url = "https://www.bungie.net/platform/app/oauth/token/"
        payload = {
            "grant_type": "authorization_code",
            "code": code,
            "client_id": os.environ.get("BUNGIE_CLIENT_ID"),
            "client_secret": os.environ.get("BUNGIE_CLIENT_SECRET"),
            "redirect_uri": os.environ.get("BUNGIE_REDIRECT_URI"),
        }
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        response = retry_request(
            requests.post, token_url, data=payload, headers=headers, timeout=self.timeout)
        response.raise_for_status()
        token_data = response.json()
        # Fetch membershipId
        membership_id_val = ""
        try:
            headers_profile = {
                "Authorization": f"Bearer {token_data.get('access_token', '')}",
                "X-API-Key": self.api_key
            }
            profile_url = f"{self.api_base}/User/GetMembershipsForCurrentUser/"
            profile_resp = retry_request(
                requests.get, profile_url, headers=headers_profile, timeout=self.timeout)
            if profile_resp.ok:
                profile_data = profile_resp.json().get("Response", {})
                if profile_data.get("destinyMemberships"):
                    membership_id_val = profile_data["destinyMemberships"][0].get(
                        "membershipId", "")
        except Exception as e:
            logging.warning(
                "[assistant] Could not retrieve membershipId: %s", e)
        # Store in Table Storage
        table_service = TableServiceClient.from_connection_string(
            self.storage_conn_str)
        table_client = table_service.get_table_client(self.table_name)
        try:
            table_client.create_table()
        except Exception:
            pass
        token_entity = {
            "PartitionKey": "AuthSession",
            "RowKey": "last",
            "AccessToken": token_data.get("access_token", ""),
            "RefreshToken": token_data.get("refresh_token", ""),
            "ExpiresIn": str(token_data.get("expires_in", "3600")),
            "membershipId": membership_id_val,
            "IssuedAt": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")
        }
        table_client.upsert_entity(entity=token_entity)
        logging.info(
            "[assistant] Token data stored in table storage for session.")
        return token_data

    def get_session(self):
        """Retrieve stored session info including access token and membership ID."""
        logging.info("Retrieving stored session.")
        entity = self._ensure_token_valid()
        if not entity:
            return {"access_token": None, "membership_id": None}
        return {
            "access_token": entity["AccessToken"],
            "membership_id": entity["membershipId"]
        }

    def initialize_user(self):
        """Authenticate user, load manifest, and fetch Destiny 2 character summary using stored session."""
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

    def get_vault(self):
        """Fetch user's Destiny 2 vault inventory and save to blob storage using stored session."""
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

    def get_characters(self):
        """Fetch user's Destiny 2 character equipment and save to blob storage using stored session."""
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

    def get_manifest_item(self, item_hash):
        """Return manifest definition for a given item hash."""
        headers = {"X-API-Key": self.api_key}
        logging.info("Fetching manifest item for hash: %s", item_hash)
        definitions = get_manifest(
            headers, self.manifest_cache, self.api_base, retry_request, self.timeout)
        definition = definitions.get(item_hash)
        if not definition:
            logging.error("Item hash %s not found in manifest.", item_hash)
            return None, 404
        logging.info("Manifest item found for hash: %s", item_hash)
        return definition, 200

    def save_dim_backup(self, membership_id, dim_json_str):
        """Save a DIM backup and its metadata."""
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

    def main_entry(self, access_token=None, vault_data_path=None):
        """Main entry for assistant: initialize with access_token or vault_data_path."""
        if not access_token and not vault_data_path:
            logging.error(
                "Missing access_token or vault_data_path in main entry.")
            return {"error": "Missing access_token or vault_data_path"}, 400
        if access_token:
            headers = {
                "Authorization": f"Bearer {access_token}",
                "X-API-Key": self.api_key
            }
            profile_url = f"{self.api_base}/User/GetMembershipsForCurrentUser/"
            logging.info("Main entry: initializing with access token.")
            profile_resp = retry_request(
                requests.get, profile_url, headers=headers, timeout=self.timeout)
            if not profile_resp.ok:
                logging.error(
                    "Failed to get membership data: status %d", profile_resp.status_code)
                return {"error": "Failed to get membership data"}, profile_resp.status_code
            profile_data = profile_resp.json().get("Response", {})
            if not profile_data.get("destinyMemberships"):
                logging.error("No Destiny memberships found in main entry.")
                return {"error": "No Destiny memberships found"}, 404
            membership = profile_data["destinyMemberships"][0]
            membership_id = membership.get("membershipId")
            membership_type = membership.get("membershipType")
            display_name = membership.get("displayName", "")
            response_payload = {
                "message": "Vault assistant initialized.",
                "membershipId": membership_id,
                "membershipType": membership_type,
                "userInfo": display_name
            }
            logging.info(
                "Main entry: assistant initialized for user: %s", membership_id)
            return response_payload, 200
        elif vault_data_path:
            response_payload = {
                "message": "Vault assistant initialized with saved data.",
                "vaultDataPath": vault_data_path,
                "stub": "Loading from vault data path not yet implemented."
            }
            logging.info(
                "Main entry: initialized with saved data path: %s", vault_data_path)
            return response_payload, 200

    def list_dim_backups(self, membership_id):
        """List available DIM backups for a given membership ID."""
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

    def refresh_token(self, refresh_token_val):
        """Refresh access token using the stored refresh token."""
        logging.info("Refreshing access token using refresh token.")
        token_url = "https://www.bungie.net/platform/app/oauth/token/"
        payload = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token_val,
            "client_id": os.environ.get("BUNGIE_CLIENT_ID"),
            "client_secret": os.environ.get("BUNGIE_CLIENT_SECRET"),
        }
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        response = retry_request(
            requests.post, token_url, data=payload, headers=headers, timeout=self.timeout)
        response.raise_for_status()
        token_data = response.json()
        logging.info("Access token refreshed successfully.")
        return token_data, 200

    def decode_vault(self) -> tuple:
        """Decode the vault inventory using manifest definitions."""
        return self._decode_blob(source="vault"), 200

    def decode_characters(self) -> tuple:
        """Decode the character equipment using manifest definitions."""
        return self._decode_blob(source="characters"), 200

    def get_session_token(self) -> tuple:
        """Return current access token and membership ID, wrapped for external use."""
        session = self.get_session()
        return {
            "access_token": session["access_token"],
            "membership_id": session["membership_id"]
        }, 200

    def _get_blob_container(self):
        """Return the blob container client for the main blob container."""
        return BlobServiceClient.from_connection_string(self.storage_conn_str).get_container_client(self.blob_container)

    def _get_manifest_definitions(self) -> dict:
        """Fetch and return manifest definitions, using cache if available."""
        headers = {"X-API-Key": self.api_key}
        return get_manifest(headers, self.manifest_cache, self.api_base, retry_request, self.timeout)

    def _decode_blob(self, source: str = 'vault') -> list:
        """Decode and enrich inventory or character data using manifest definitions."""
        logging.info("Starting decode pass for source: %s", source)
        session = self.get_session()
        membership_id = session["membership_id"]
        blob_name = f"{membership_id}.json" if source == "vault" else f"{membership_id}-characters.json"
        container = self._get_blob_container()
        blob_data = container.download_blob(blob_name).readall()
        items = json.loads(blob_data)
        definitions = self._get_manifest_definitions()
        decoded_items = []
        if isinstance(items, list):  # Vault
            for item in items:
                item_hash = str(item.get("itemHash"))
                defn = definitions.get(item_hash, {})
                decoded_items.append({
                    "name": defn.get("displayProperties", {}).get("name", "Unknown"),
                    "type": defn.get("itemTypeDisplayName", "Unknown"),
                    "itemHash": item.get("itemHash"),
                    "itemInstanceId": item.get("itemInstanceId"),
                })
        elif isinstance(items, dict):  # Characters
            for char_id, char_data in items.items():
                char_items = char_data.get("items", [])
                enriched_items = []
                for item in char_items:
                    item_hash = str(item.get("itemHash"))
                    defn = definitions.get(item_hash, {})
                    enriched_items.append({
                        "name": defn.get("displayProperties", {}).get("name", "Unknown"),
                        "type": defn.get("itemTypeDisplayName", "Unknown"),
                        "itemHash": item.get("itemHash"),
                        "itemInstanceId": item.get("itemInstanceId"),
                    })
                decoded_items.append({
                    "characterId": char_id,
                    "items": enriched_items
                })
        logging.info("Decode pass complete for source: %s", source)
        return decoded_items
