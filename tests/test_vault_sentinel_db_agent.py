"""Unit tests for VaultSentinelDBAgent."""
# pylint: disable=import-error,protected-access
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy.exc import SQLAlchemyError

from VaultSentinelPlatform.agent.db_agent import VaultSentinelDBAgent
from VaultSentinelPlatform.exceptions import DependencyUnavailableError, QueryValidationError


def get_valid_query():
    """
    Returns a valid query for testing.
    """
    return {
        "intent": "list_items_by_stat",
        "filters": {"statThreshold": {"gte": 65, "stat": "Discipline"}, "type": "armor"},
        "output": {"includePerks": True, "includeStats": True, "includeInstanceData": True},
        "sort": {"field": "statValue", "direction": "desc"},
        "limit": 25
    }


def test_process_query_success():
    """Test successful processing of a valid query."""
    VaultSentinelDBAgent.reset_instance()
    agent = VaultSentinelDBAgent.instance()
    # Patch chat_client and session_factory
    agent.chat_client = MagicMock()
    agent.chat_client.chat.completions.create.return_value = MagicMock(
        choices=[MagicMock(message=MagicMock(content="SELECT * FROM items"))]
    )
    mock_session = MagicMock()
    mock_result = MagicMock()
    mock_result.fetchall.return_value = [("item1", "stat1")]
    mock_result.keys.return_value = ["name", "stat"]
    mock_session.execute.return_value = mock_result
    agent.session_factory = MagicMock(return_value=mock_session)

    with patch("builtins.open", MagicMock()), patch("json.dumps", MagicMock()):
        result = agent.process_query(get_valid_query())
        assert result["status"] == "success"
        assert "data" in result
        assert "sql" in result


def test_process_query_invalid_query():
    """Test processing of an invalid query."""
    VaultSentinelDBAgent.reset_instance()
    agent = VaultSentinelDBAgent.instance()
    invalid_query = {"intent": None}
    with pytest.raises(QueryValidationError):
        agent.process_query(invalid_query)


def test_get_session_with_cold_start_handling_translates_sqlalchemy_error() -> None:
    """Unexpected SQLAlchemy failures should surface as typed dependency errors."""
    VaultSentinelDBAgent.reset_instance()
    agent = VaultSentinelDBAgent.instance()
    agent.session_factory = MagicMock()
    agent._connection_warmed = True

    with patch.object(agent, "_open_validated_session", side_effect=SQLAlchemyError("driver offline")):
        with pytest.raises(DependencyUnavailableError) as exc_info:
            agent._get_session_with_cold_start_handling()

    assert exc_info.value.details["dependency"] == "database_session"
    assert exc_info.value.__cause__ is not None


def test_process_query_redacts_dependency_error_details() -> None:
    """HTTP-facing query failures should not expose raw infrastructure exception text."""
    VaultSentinelDBAgent.reset_instance()
    agent = VaultSentinelDBAgent.instance()
    agent.chat_client = MagicMock()
    agent.chat_client.chat.completions.create.return_value = MagicMock(
        choices=[MagicMock(message=MagicMock(content="SELECT * FROM items"))]
    )
    agent.session_factory = MagicMock()

    with (
        patch("builtins.open", MagicMock()),
        patch.object(
            agent,
            "_get_session_with_cold_start_handling",
            side_effect=DependencyUnavailableError(
                "driver offline",
                details={"dependency": "database_session"},
            ),
        ),
    ):
        result = agent.process_query(get_valid_query())

    assert result == {
        "status": "error",
        "error": "Database dependency unavailable. Check configuration and logs.",
    }
