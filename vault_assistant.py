import json
import logging
import os

import requests
from azure.storage.blob import BlobServiceClient  # Module-level import as preferred

from helpers import (get_manifest, retry_request, save_blob,
                     save_dim_backup_blob)


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

    def initialize_user(self, access_token):
        """Authenticate user, load manifest, and fetch Destiny 2 character summary."""
        headers = {
            "Authorization": f"Bearer {access_token}",
            "X-API-Key": self.api_key
        }
        profile_url = f"{self.api_base}/User/GetMembershipsForCurrentUser/"
        logging.info("Initializing user with access token.")
        profile_resp = retry_request(
            requests.get, profile_url, headers=headers, timeout=self.timeout)
        if not profile_resp.ok:
            logging.error("Failed to get membership: status %d", profile_resp.status_code)
            return None, profile_resp.status_code
        profile_data = profile_resp.json()["Response"]
        if not profile_data.get("destinyMemberships"):
            logging.error("No Destiny memberships found for user.")
            return None, 404
        membership = profile_data["destinyMemberships"][0]
        membership_id = membership["membershipId"]
        membership_type = membership["membershipType"]
        # Confirm manifest is loaded
        get_manifest(headers, self.manifest_cache, self.api_base, retry_request, self.timeout)
        # Get character list
        characters_url = f"{self.api_base}/Destiny2/{membership_type}/Profile/{membership_id}/?components=200"
        char_resp = retry_request(
            requests.get, characters_url, headers=headers, timeout=self.timeout)
        if not char_resp.ok:
            logging.error("Failed to get characters: status %d", char_resp.status_code)
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

    def get_vault(self, access_token):
        """Fetch user's Destiny 2 vault inventory and save to blob storage."""
        headers = {
            "Authorization": f"Bearer {access_token}",
            "X-API-Key": self.api_key
        }
        profile_url = f"{self.api_base}/User/GetMembershipsForCurrentUser/"
        logging.info("Fetching vault for user.")
        profile_resp = retry_request(
            requests.get, profile_url, headers=headers, timeout=self.timeout)
        if not profile_resp.ok:
            logging.error("Failed to get membership: status %d", profile_resp.status_code)
            return None, profile_resp.status_code
        profile_data = profile_resp.json()["Response"]
        membership = profile_data["destinyMemberships"][0]
        membership_id = membership["membershipId"]
        membership_type = membership["membershipType"]
        inventory_url = f"{self.api_base}/Destiny2/{membership_type}/Profile/{membership_id}/?components=102"
        inv_resp = retry_request(
            requests.get, inventory_url, headers=headers, timeout=self.timeout)
        if not inv_resp.ok:
            logging.error("Failed to get vault inventory: status %d", inv_resp.status_code)
            return None, inv_resp.status_code
        inventory = inv_resp.json()["Response"]["profileInventory"]["data"]["items"]
        save_blob(self.storage_conn_str, self.blob_container, f"{membership_id}.json", json.dumps(inventory))
        logging.info("Vault inventory fetched and saved for user: %s", membership_id)
        return inventory, 200

    def get_characters(self, access_token):
        """Fetch user's Destiny 2 character equipment and save to blob storage."""
        headers = {
            "Authorization": f"Bearer {access_token}",
            "X-API-Key": self.api_key
        }
        profile_url = f"{self.api_base}/User/GetMembershipsForCurrentUser/"
        logging.info("Fetching character equipment for user.")
        profile_resp = retry_request(
            requests.get, profile_url, headers=headers, timeout=self.timeout)
        if not profile_resp.ok:
            logging.error("Failed to get membership: status %d", profile_resp.status_code)
            return None, profile_resp.status_code
        profile_data = profile_resp.json()["Response"]
        membership = profile_data["destinyMemberships"][0]
        membership_id = membership["membershipId"]
        membership_type = membership["membershipType"]
        char_url = f"{self.api_base}/Destiny2/{membership_type}/Profile/{membership_id}/?components=205"
        char_resp = retry_request(
            requests.get, char_url, headers=headers, timeout=self.timeout)
        if not char_resp.ok:
            logging.error("Failed to get character equipment: status %d", char_resp.status_code)
            return None, char_resp.status_code
        equipment = char_resp.json()["Response"]["characterEquipment"]["data"]
        save_blob(self.storage_conn_str, self.blob_container, f"{membership_id}-characters.json", json.dumps(equipment))
        logging.info("Character equipment fetched and saved for user: %s", membership_id)
        return equipment, 200

    def get_manifest_item(self, item_hash):
        """Return manifest definition for a given item hash."""
        headers = {"X-API-Key": self.api_key}
        logging.info("Fetching manifest item for hash: %s", item_hash)
        definitions = get_manifest(headers, self.manifest_cache, self.api_base, retry_request, self.timeout)
        definition = definitions.get(item_hash)
        if not definition:
            logging.error("Item hash %s not found in manifest.", item_hash)
            return None, 404
        logging.info("Manifest item found for hash: %s", item_hash)
        return definition, 200

    def save_dim_backup(self, membership_id, dim_json_str):
        """Save a DIM backup and its metadata."""
        logging.info("Saving DIM backup for user: %s", membership_id)
        save_dim_backup_blob(self.storage_conn_str, self.table_name, membership_id, dim_json_str)
        logging.info("DIM backup saved for user: %s", membership_id)
        return True

    def main_entry(self, access_token=None, vault_data_path=None):
        """Main entry for assistant: initialize with access_token or vault_data_path."""
        if not access_token and not vault_data_path:
            logging.error("Missing access_token or vault_data_path in main entry.")
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
                logging.error("Failed to get membership data: status %d", profile_resp.status_code)
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
            logging.info("Main entry: assistant initialized for user: %s", membership_id)
            return response_payload, 200
        elif vault_data_path:
            response_payload = {
                "message": "Vault assistant initialized with saved data.",
                "vaultDataPath": vault_data_path,
                "stub": "Loading from vault data path not yet implemented."
            }
            logging.info("Main entry: initialized with saved data path: %s", vault_data_path)
            return response_payload, 200

    def list_dim_backups(self, membership_id):
        """List available DIM backups for a given membership ID."""
        logging.info("Listing DIM backups for user: %s", membership_id)
        blob_service = BlobServiceClient.from_connection_string(self.storage_conn_str)
        container = blob_service.get_container_client("dim-backups")
        blobs = container.list_blobs(name_starts_with=f"dim-backup-{membership_id}-")
        blob_names = [blob.name for blob in blobs]
        logging.info("Found %d DIM backups for user: %s", len(blob_names), membership_id)
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
        response = retry_request(requests.post, token_url, data=payload, headers=headers, timeout=self.timeout)
        response.raise_for_status()
        token_data = response.json()
        logging.info("Access token refreshed successfully.")
        return token_data, 200
