"""
BungieSessionManager: Handles OAuth authentication, token refresh, and session management for Destiny 2 Vault Assistant.

Responsibilities:
- Exchange OAuth code for access/refresh tokens
- Refresh tokens when expired
- Store/retrieve session info in Azure Table Storage
- Provide current session (access token, membership ID)
"""
import os
import logging
from datetime import datetime
import requests
from azure.data.tables import TableServiceClient
from azure.core.exceptions import ResourceNotFoundError, AzureError, ResourceExistsError
from helpers import retry_request

class BungieSessionManager:
    def __init__(self, api_key: str, storage_conn_str: str, table_name: str, api_base: str, timeout: int):
        self.api_key = api_key
        self.storage_conn_str = storage_conn_str
        self.table_name = table_name
        self.api_base = api_base
        self.timeout = timeout
        self._token_expiry_margin = 60  # seconds before expiry to refresh

    def _get_token_entity(self) -> dict | None:
        table_service = TableServiceClient.from_connection_string(self.storage_conn_str)
        table_client = table_service.get_table_client(self.table_name)
        try:
            entity = table_client.get_entity(partition_key="AuthSession", row_key="last")
            return entity
        except ResourceNotFoundError:
            return None
        except AzureError as e:
            logging.error("Azure Table error in _get_token_entity: %s", e)
            return None

    def _is_token_expired(self) -> bool:
        entity = self._get_token_entity()
        if not entity:
            return True
        expires_in = int(entity.get("ExpiresIn", "3600"))
        issued_at = entity.get("IssuedAt")
        if not issued_at:
            return True
        issued_at_dt = datetime.strptime(issued_at, "%Y-%m-%dT%H:%M:%S")
        now = datetime.utcnow()
        elapsed = (now - issued_at_dt).total_seconds()
        return elapsed > (expires_in - self._token_expiry_margin)

    def ensure_token_valid(self) -> dict | None:
        entity = self._get_token_entity()
        if not entity:
            return None
        if self._is_token_expired():
            refresh_token_val = entity.get("RefreshToken")
            if refresh_token_val:
                token_data, _ = self.refresh_token(refresh_token_val)
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
                    membership_id_val = profile_data["destinyMemberships"][0].get("membershipId", "")
        except requests.RequestException as e:
            logging.warning("[session] Could not retrieve membershipId due to network error: %s", e)
        except (KeyError, ValueError) as e:
            logging.warning("[session] Could not parse membershipId: %s", e)
        # Store in Table Storage
        table_service = TableServiceClient.from_connection_string(self.storage_conn_str)
        table_client = table_service.get_table_client(self.table_name)
        try:
            table_client.create_table()
        except ResourceExistsError:
            pass
        except AzureError as e:
            logging.warning("[session] Azure Table error on create_table: %s", e)
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
        logging.info("[session] Token data stored in table storage for session.")
        return token_data

    def get_session(self) -> dict:
        entity = self.ensure_token_valid()
        if not entity:
            return {"access_token": None, "membership_id": None}
        return {
            "access_token": entity["AccessToken"],
            "membership_id": entity["membershipId"]
        }

    def refresh_token(self, refresh_token_val: str) -> tuple[dict, int]:
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
