# pyright: reportMissingImports=false
# pylint: disable=protected-access
"""Exception-handling regression tests for `VaultAssistant`."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from azure.core.exceptions import AzureError
from sqlalchemy.exc import SQLAlchemyError

from VaultSentinelPlatform.bungie.session_manager import BungieSessionManager
from VaultSentinelPlatform.exceptions import DependencyUnavailableError
from VaultSentinelPlatform.vault.assistant import VaultAssistant


class _FakeItem:
    """Simple item test double with the expected model API."""

    def __init__(self, payload: dict) -> None:
        self._payload = payload

    def model_dump(self) -> dict:
        """Simulate the Pydantic model_dump method used in VaultModel.from_components."""
        return self._payload


def _build_assistant() -> VaultAssistant:
    """Create a lightweight assistant instance for exception tests."""
    return VaultAssistant(
        api_key="test-key",
        storage_conn_str="UseDevelopmentStorage=true",
        table_name="sessions",
        blob_container="vault",
        api_base="https://example.test",
        timeout=5,
    )


def test_save_object_redacts_internal_error_details() -> None:
    """HTTP-facing save failures should not expose low-level exception text."""
    assistant = _build_assistant()
    mime_object = SimpleNamespace(
        filename="example.txt",
        content_type="text/plain",
        content="payload",
    )

    with patch(
        "VaultSentinelPlatform.vault.assistant.save_blob",
        side_effect=AzureError("storage secret should stay in logs"),
    ):
        result, status = assistant.save_object(mime_object)

    assert status == 500
    assert result == {"error": "Failed to save object. Check logs."}


def test_decode_vault_degrades_gracefully_for_typed_dependency_errors() -> None:
    """Expected dependency outages may be logged and skipped without breaking the request."""
    assistant = _build_assistant()
    fake_vault_model = SimpleNamespace(items=[_FakeItem({"itemHash": "123"})])
    fake_db_agent = SimpleNamespace(
        session_factory=object(),
        persist_vault=MagicMock(
            side_effect=DependencyUnavailableError("Database temporarily unavailable")
        ),
    )

    with (
        patch.object(assistant, "get_session", return_value={
            "membership_id": "member-1",
            "membership_type": "3",
            "access_token": "token",
        }),
        patch.object(assistant, "get_bungie_profile_last_modified", return_value=(None, 200)),
        patch("VaultSentinelPlatform.vault.assistant.load_blob", return_value=b"[{\"itemHash\": \"123\"}]"),
        patch("VaultSentinelPlatform.vault.assistant.save_blob"),
        patch.object(assistant, "_fetch_item_components_map", return_value={}),
        patch("VaultSentinelPlatform.vault.assistant.VaultModel.from_components", return_value=fake_vault_model),
        patch("VaultSentinelPlatform.vault.assistant.VaultSentinelDBAgent.is_db_configured", return_value=True),
        patch("VaultSentinelPlatform.vault.assistant.VaultSentinelDBAgent.instance", return_value=fake_db_agent),
    ):
        result, status = assistant.decode_vault()

    assert status == 200
    assert result == [{"itemHash": "123"}]


def test_decode_vault_propagates_raw_sqlalchemy_errors() -> None:
    """Raw ORM failures should not be swallowed at the assistant boundary."""
    assistant = _build_assistant()
    fake_vault_model = SimpleNamespace(items=[_FakeItem({"itemHash": "123"})])
    fake_db_agent = SimpleNamespace(
        session_factory=object(),
        persist_vault=MagicMock(side_effect=SQLAlchemyError("insert failed")),
    )

    with (
        patch.object(assistant, "get_session", return_value={
            "membership_id": "member-1",
            "membership_type": "3",
            "access_token": "token",
        }),
        patch.object(assistant, "get_bungie_profile_last_modified", return_value=(None, 200)),
        patch("VaultSentinelPlatform.vault.assistant.load_blob", return_value=b"[{\"itemHash\": \"123\"}]"),
        patch("VaultSentinelPlatform.vault.assistant.save_blob"),
        patch.object(assistant, "_fetch_item_components_map", return_value={}),
        patch("VaultSentinelPlatform.vault.assistant.VaultModel.from_components", return_value=fake_vault_model),
        patch("VaultSentinelPlatform.vault.assistant.VaultSentinelDBAgent.is_db_configured", return_value=True),
        patch("VaultSentinelPlatform.vault.assistant.VaultSentinelDBAgent.instance", return_value=fake_db_agent),
    ):
        with pytest.raises(SQLAlchemyError, match="insert failed"):
            assistant.decode_vault()


def test_decode_vault_propagates_unexpected_programming_errors() -> None:
    """Unexpected implementation bugs should not be silently swallowed as dependency issues."""
    assistant = _build_assistant()
    fake_vault_model = SimpleNamespace(items=[_FakeItem({"itemHash": "123"})])
    fake_db_agent = SimpleNamespace(
        session_factory=object(),
        persist_vault=MagicMock(side_effect=AttributeError("programming bug")),
    )

    with (
        patch.object(assistant, "get_session", return_value={
            "membership_id": "member-1",
            "membership_type": "3",
            "access_token": "token",
        }),
        patch.object(assistant, "get_bungie_profile_last_modified", return_value=(None, 200)),
        patch("VaultSentinelPlatform.vault.assistant.load_blob", return_value=b"[{\"itemHash\": \"123\"}]"),
        patch("VaultSentinelPlatform.vault.assistant.save_blob"),
        patch.object(assistant, "_fetch_item_components_map", return_value={}),
        patch("VaultSentinelPlatform.vault.assistant.VaultModel.from_components", return_value=fake_vault_model),
        patch("VaultSentinelPlatform.vault.assistant.VaultSentinelDBAgent.is_db_configured", return_value=True),
        patch("VaultSentinelPlatform.vault.assistant.VaultSentinelDBAgent.instance", return_value=fake_db_agent),
    ):
        with pytest.raises(AttributeError, match="programming bug"):
            assistant.decode_vault()


def test_session_manager_get_token_entity_translates_azure_table_failures() -> None:
    """Configured session storage outages should surface as typed dependency errors."""
    manager = BungieSessionManager(
        api_key="test-key",
        storage_conn_str="UseDevelopmentStorage=true",
        table_name="sessions",
        api_base="https://example.test",
        timeout=5,
    )
    fake_table = SimpleNamespace(get_entity=MagicMock(side_effect=AzureError("table unavailable")))

    with patch.object(manager, "_get_table_client", return_value=fake_table):
        with pytest.raises(DependencyUnavailableError, match="Session storage is unavailable") as exc_info:
            manager._get_token_entity()

    assert exc_info.value.__cause__ is not None
    assert exc_info.value.details == {"dependency": "azure_table_storage", "table": "sessions"}
