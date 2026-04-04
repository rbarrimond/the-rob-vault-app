#pylint: disable=line-too-long
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
from _thread import LockType
from datetime import datetime, timezone
from typing import ClassVar

import requests
from azure.core.exceptions import (AzureError, ResourceExistsError,
                                   ResourceNotFoundError)
from azure.data.tables import TableServiceClient

from VaultSentinelPlatform.common.helpers import retry_request
from VaultSentinelPlatform.config import (
    API_KEY,
    BUNGIE_API_BASE,
    REQUEST_TIMEOUT,
    STORAGE_CONNECTION_STRING,
    TABLE_NAME,
)
from VaultSentinelPlatform.exceptions import DependencyUnavailableError


ISSUED_AT_FORMAT = "%Y-%m-%dT%H:%M:%S"


class BungieSessionManager:
    """
    Handles OAuth authentication, token refresh, and session management for Destiny 2 Vault Assistant.

    Responsibilities:
        - Exchange OAuth code for access/refresh tokens
        - Refresh tokens when expired
        - Store/retrieve session info in Azure Table Storage
        - Persist and provide current session (access token, membershipId, membershipType)
    """

    _instance: ClassVar["BungieSessionManager | None"] = None
    _lock: ClassVar[LockType | None] = None

    @classmethod
    def _get_lock(cls) -> LockType:
        """Return the singleton lock, creating it on first use."""
        if cls._lock is None:
            cls._lock = threading.Lock()
        return cls._lock

    @classmethod
    def instance(cls, *args, **kwargs) -> "BungieSessionManager":
        """
        Singleton factory method for BungieSessionManager.
        Ensures token is valid on first creation.
        """
        if cls._instance is None:
            #pylint: disable=protected-access, not-context-manager
            with cls._get_lock():
                if cls._instance is None:
                    cls._instance = cls(*args, **kwargs)
                    try:
                        cls._instance._ensure_token_valid()
                    except DependencyUnavailableError as exc:
                        logging.warning(
                            "[session] Initial token validation skipped because session storage is unavailable: %s",
                            exc,
                            exc_info=True,
                        )
        return cls._instance

    def __init__(
        self,
        api_key: str | None = API_KEY,
        storage_conn_str: str | None = STORAGE_CONNECTION_STRING,
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
        self.api_key = api_key or ""
        self.storage_conn_str = storage_conn_str or ""
        self.table_name = table_name
        self.api_base = api_base
        self.timeout = timeout
        self._token_expiry_margin = 60  # seconds before expiry to refresh
        self._session_cache = None  # In-memory cache for session entity
        self._session_last_checked = None

    @staticmethod
    def _raise_dependency_unavailable(
        message: str,
        *,
        cause: Exception | None = None,
        **details,
    ) -> None:
        """Raise a typed dependency error while preserving the original cause."""
        error = DependencyUnavailableError(message, details=details)
        if cause is None:
            raise error
        raise error from cause

    def _get_table_client(self):
        """Return the session table client when storage is configured, else `None`."""
        if not self.storage_conn_str:
            logging.warning("[session] Azure Storage connection string is not configured.")
            return None
        try:
            table_service = TableServiceClient.from_connection_string(self.storage_conn_str)
            return table_service.get_table_client(self.table_name)
        except (AzureError, ValueError) as exc:
            logging.error("[session] Failed to initialize Azure Table client: %s", exc, exc_info=True)
            self._raise_dependency_unavailable(
                "Session storage is unavailable.",
                cause=exc,
                dependency="azure_table_storage",
                table=self.table_name,
            )

    def _get_token_entity(self) -> dict | None:
        """
        Retrieve the token entity from Azure Table Storage.

        Returns:
            dict | None: Token entity if found, else None.
        """
        table_client = self._get_table_client()
        if table_client is None:
            return None
        try:
            entity = table_client.get_entity(partition_key="AuthSession", row_key="last")
            self._session_cache = entity
            return entity
        except ResourceNotFoundError:
            return None
        except AzureError as exc:
            logging.error("Azure Table error in _get_token_entity: %s", exc, exc_info=True)
            self._raise_dependency_unavailable(
                "Session storage is unavailable.",
                cause=exc,
                dependency="azure_table_storage",
                table=self.table_name,
            )

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
        try:
            expires_in = int(entity.get("ExpiresIn", "3600"))
        except (TypeError, ValueError):
            expires_in = 3600
        issued_at = entity.get("IssuedAt")
        if not issued_at:
            return True
        try:
            issued_at_dt = datetime.strptime(issued_at, ISSUED_AT_FORMAT)
        except (TypeError, ValueError):
            return True
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        elapsed = (now - issued_at_dt).total_seconds()
        return elapsed > (expires_in - self._token_expiry_margin)

    def _persist_session_entity(self, entity: dict, *, context: str) -> None:
        """Persist the session entity when table storage is configured."""
        try:
            table_client = self._get_table_client()
        except DependencyUnavailableError as exc:
            logging.warning(
                "[session] Session entity persistence skipped during %s because storage is unavailable: %s",
                context,
                exc,
                exc_info=True,
            )
            return
        if table_client is None:
            return
        try:
            table_client.upsert_entity(entity=entity)
        except AzureError as exc:
            logging.warning("[session] Azure Table upsert failed during %s: %s", context, exc, exc_info=True)

    def _refresh_cached_entity(self, entity: dict, refresh_token_val: str) -> None:
        """Refresh the cached token payload and persist the updated session entity."""
        try:
            token_data, _ = self.refresh_token(refresh_token_val)
        except (requests.RequestException, DependencyUnavailableError, TypeError, ValueError) as exc:
            logging.warning(
                "[session] Token refresh failed; using cached entity if available: %s",
                exc,
                exc_info=True,
            )
            return

        entity.update({
            "AccessToken": token_data.get("access_token", ""),
            "RefreshToken": token_data.get("refresh_token", ""),
            "ExpiresIn": str(token_data.get("expires_in", "3600")),
            "IssuedAt": datetime.now(timezone.utc).strftime(ISSUED_AT_FORMAT),
        })
        self._persist_session_entity(entity, context="refresh")
        self._session_cache = entity

    def _ensure_token_valid(self) -> dict | None:
        """
        Ensure the token is valid, refreshing if expired. Private.

        Returns:
            dict | None: Valid token entity, or None if not found.
        """
        entity = self._session_cache or self._get_token_entity()
        if not entity:
            return None
        if self._is_token_expired(entity):
            refresh_token_val = entity.get("RefreshToken")
            if refresh_token_val:
                self._refresh_cached_entity(entity, refresh_token_val)
        else:
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
        except (requests.RequestException, DependencyUnavailableError) as exc:
            logging.warning(
                "[session] Could not retrieve membership info due to dependency error: %s",
                exc,
                exc_info=True,
            )
        except (TypeError, ValueError) as exc:
            logging.warning("[session] Could not parse membership info: %s", exc, exc_info=True)
        # Store in Table Storage
        table_client = self._get_table_client()
        if table_client is not None:
            try:
                table_client.create_table()
            except ResourceExistsError:
                logging.debug("[session] Table '%s' already exists; continuing.", self.table_name)
            except AzureError as exc:
                logging.warning("[session] Azure Table error on create_table: %s", exc, exc_info=True)
        token_entity = {
            "PartitionKey": "AuthSession",
            "RowKey": "last",
            "AccessToken": token_data.get("access_token", ""),
            "RefreshToken": token_data.get("refresh_token", ""),
            "ExpiresIn": str(token_data.get("expires_in", "3600")),
            "membershipId": membership_id_val,
            "membershipType": membership_type_val,
            "IssuedAt": datetime.now(timezone.utc).strftime(ISSUED_AT_FORMAT)
        }
        if table_client is not None:
            try:
                table_client.upsert_entity(entity=token_entity)
                logging.info("[session] Token data stored in table storage for session.")
            except AzureError as exc:
                logging.warning("[session] Azure Table error on upsert_entity: %s", exc, exc_info=True)
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
        try:
            profile_root = profile_resp.json()
        except ValueError as e:
            logging.warning("[session] Invalid JSON in membership profile response: %s", e)
            return None
        profile_data = profile_root.get("Response", {})
        if not profile_data.get("destinyMemberships"):
            return None
        membership = profile_data["destinyMemberships"][0]
        return membership.get("membershipId", ""), membership.get("membershipType", "1")
