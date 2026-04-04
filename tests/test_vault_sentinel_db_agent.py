"""Unit tests for VaultSentinelDBAgent."""
# pylint: disable=import-error,protected-access
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy.exc import SQLAlchemyError

from VaultSentinelPlatform.agent.db_agent import VaultSentinelDBAgent
from VaultSentinelPlatform.exceptions import (
    BusinessRuleViolationError,
    ConfigurationError,
    DependencyUnavailableError,
    QueryValidationError,
)


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


def test_process_query_raises_dependency_error_for_http_adapter() -> None:
    """Database dependency failures should stay typed for the HTTP adapter to translate."""
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
        with pytest.raises(DependencyUnavailableError, match="driver offline"):
            agent.process_query(get_valid_query())


def test_process_query_raises_configuration_error_when_openai_not_configured() -> None:
    """Missing Azure OpenAI configuration should surface as a typed configuration error."""
    VaultSentinelDBAgent.reset_instance()
    agent = VaultSentinelDBAgent.instance()
    agent.chat_client = None
    agent.session_factory = MagicMock()

    with pytest.raises(ConfigurationError, match="Azure OpenAI client is not configured"):
        agent.process_query(get_valid_query())


def test_process_query_raises_business_rule_violation_for_rejected_sql() -> None:
    """Unsafe AI-generated SQL should be rejected as a business-rule failure, not a generic error dict."""
    VaultSentinelDBAgent.reset_instance()
    agent = VaultSentinelDBAgent.instance()
    agent.chat_client = MagicMock()
    agent.chat_client.chat.completions.create.return_value = MagicMock(
        choices=[MagicMock(message=MagicMock(content="DELETE FROM items"))]
    )
    agent.session_factory = MagicMock()

    with (
        patch("builtins.open", MagicMock()),
        patch("json.dumps", MagicMock()),
    ):
        with pytest.raises(BusinessRuleViolationError, match="Generated SQL violated Vault Sentinel safety rules"):
            agent.process_query(get_valid_query())

