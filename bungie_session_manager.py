#pylint: disable=broad-except, line-too-long
"""
BungieSessionManager: Handles OAuth authentication, token refresh, and session management for Destiny 2 Vault Assistant.

Responsibilities:
- Exchange OAuth code for access/refresh tokens
- Refresh tokens when expired
- Store/retrieve session info in Azure Table Storage
- Provide current session (access token, membership ID)
"""
import logging
import os
import threading
from datetime import datetime, timezone

import requests
from azure.core.exceptions import (AzureError, ResourceExistsError,
                                   ResourceNotFoundError)
from azure.data.tables import TableServiceClient

from constants import (API_KEY, BUNGIE_API_BASE, REQUEST_TIMEOUT,
                       STORAGE_CONNECTION_STRING, TABLE_NAME)
from helpers import retry_request


class BungieSessionManager:
    """
    Handles OAuth authentication, token refresh, and session management for Destiny 2 Vault Assistant.

    Responsibilities:
        - Exchange OAuth code for access/refresh tokens
        - Refresh tokens when expired
        - Store/retrieve session info in Azure Table Storage
        - Persist and provide current session (access token, membershipId, membershipType)
    """

    _instance = None
    _lock:threading.Lock = None

    @classmethod
    def instance(cls, *args, **kwargs):
        """
        Singleton factory method for BungieSessionManager.
        Ensures token is valid on first creation.
        """
        if cls._lock is None:
            cls._lock = threading.Lock()
        if cls._instance is None:
            #pylint: disable=protected-access, not-context-manager
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls(*args, **kwargs)
                    cls._instance._ensure_token_valid()
        return cls._instance

    def __init__(
        self,
        api_key: str = API_KEY,
        storage_conn_str: str = STORAGE_CONNECTION_STRING,
        table_name: str = TABLE_NAME,
        api_base: str = BUNGIE_API_BASE,
        timeout: int = REQUEST_TIMEOUT
    ):
        """
        Initialize BungieSessionManager with configuration and dependencies.

        Args:
            api_key (str): Bungie API key.
            storage_conn_str (str): Azure Storage connection string.
            table_name (str): Azure Table name for session storage.
            api_base (str): Bungie API base URL.
            timeout (int): Request timeout in seconds.
        """
        self.api_key = api_key
        self.storage_conn_str = storage_conn_str
        self.table_name = table_name
        self.api_base = api_base
        self.timeout = timeout
        self._token_expiry_margin = 60  # seconds before expiry to refresh
        self._session_cache = None  # In-memory cache for session entity
        self._session_last_checked = None

    def _get_token_entity(self) -> dict | None:
        """
        Retrieve the token entity from Azure Table Storage.

        Returns:
            dict | None: Token entity if found, else None.
        """
        table_service = TableServiceClient.from_connection_string(self.storage_conn_str)
        table_client = table_service.get_table_client(self.table_name)
        try:
            entity = table_client.get_entity(partition_key="AuthSession", row_key="last")
            self._session_cache = entity
            return entity
        except ResourceNotFoundError:
            return None
        except AzureError as e:
            logging.error("Azure Table error in _get_token_entity: %s", e)
            return None

    def _is_token_expired(self, entity: dict | None = None) -> bool:
        """
        Check if the current token is expired or near expiry.

        Returns:
            bool: True if expired or near expiry, False otherwise.
        """
        if entity is None:
            entity = self._session_cache
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

    def _ensure_token_valid(self) -> dict | None:
        """
        Ensure the token is valid, refreshing if expired. Private.

        Returns:
            dict | None: Valid token entity, or None if not found.
        """
        # Use cache if available
        entity = self._session_cache
        if entity is None:
            # First time: fetch from table
            entity = self._get_token_entity()
        if not entity:
            return None
        if self._is_token_expired(entity):
            # Token expired, refresh from Bungie API
            refresh_token_val = entity.get("RefreshToken")
            if refresh_token_val:
                token_data, _ = self.refresh_token(refresh_token_val)
                entity.update({
                    "AccessToken": token_data.get("access_token", ""),
                    "RefreshToken": token_data.get("refresh_token", ""),
                    "ExpiresIn": str(token_data.get("expires_in", "3600")),
                    "IssuedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
                })
                table_service = TableServiceClient.from_connection_string(self.storage_conn_str)
                table_client = table_service.get_table_client(self.table_name)
                table_client.upsert_entity(entity=entity)
                self._session_cache = entity
        else:
            # Token is valid, just use cache
            self._session_cache = entity
        return self._session_cache

    def exchange_code_for_token(self, code: str) -> dict:
        """
        Exchange OAuth code for access/refresh token, store in Table Storage, and return token data.

        Persists membershipId and membershipType in Table Storage for future session retrieval.

        Args:
            code (str): OAuth authorization code received from Bungie OAuth flow.

        Returns:
            dict: Token data from Bungie API, including access and refresh tokens.
        """
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
        # Fetch membershipId and membershipType
        membership_id_val = ""
        membership_type_val = ""
        try:
            access_token_val = token_data.get('access_token', '')
            membership_info = self._get_membership_info(access_token_val)
            if membership_info:
                membership_id_val, membership_type_val = membership_info
        except requests.RequestException as e:
            logging.warning("[session] Could not retrieve membership info due to network error: %s", e)
        except (KeyError, ValueError) as e:
            logging.warning("[session] Could not parse membership info: %s", e)
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
            "membershipType": membership_type_val,
            "IssuedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
        }
        table_client.upsert_entity(entity=token_entity)
        logging.info("[session] Token data stored in table storage for session.")
        # Update in-memory cache after token exchange
        self._session_cache = token_entity
        return token_data

    def get_session(self) -> dict:
        """
        Retrieve stored session info including access token, membershipId, and membershipType.

        Returns:
            dict: Session info with keys:
                - access_token (str): OAuth access token
                - membershipId (str): Destiny membership ID
                - membershipType (str): Destiny membership type
        """
        entity = self._session_cache
        if not entity:
            return {"access_token": None, "membership_id": None, "membership_type": None}
        return {
            "access_token": entity["AccessToken"],
            "membership_id": entity["membershipId"],
            "membership_type": entity["membershipType"],
        }

    def refresh_token(self, refresh_token_val: str) -> tuple[dict, int]:
        """
        Refresh access token using the stored refresh token.

        Args:
            refresh_token_val (str): The refresh token value from previous authentication.

        Returns:
            tuple:
                - token_data (dict): New token data from Bungie API
                - status_code (int): HTTP status code (200 if successful)
        """
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

    def _get_membership_info(self, access_token: str) -> tuple[str, str] | None:
        """
        (Private) Fetch the Destiny membershipId and membershipType for the current user using the access token.
        Used only for initial token exchange and refresh. Clients should use get_session() for membership info.

        Args:
            access_token (str): OAuth access token for Bungie API.

        Returns:
            tuple:
                - membershipId (str): Destiny membership ID
                - membershipType (str): Destiny membership type
            or None if not found.
        """
        headers_profile = {
            "Authorization": f"Bearer {access_token}",
            "X-API-Key": self.api_key
        }
        profile_url = f"{self.api_base}/User/GetMembershipsForCurrentUser/"
        profile_resp = retry_request(
            requests.get, profile_url, headers=headers_profile, timeout=self.timeout)
        if not profile_resp.ok:
            return None
        profile_data = profile_resp.json().get("Response", {})
        if not profile_data.get("destinyMemberships"):
            return None
        membership = profile_data["destinyMemberships"][0]
        return membership.get("membershipId", ""), membership.get("membershipType", "1")
