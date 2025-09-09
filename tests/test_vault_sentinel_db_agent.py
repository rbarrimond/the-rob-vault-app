"""Unit tests for VaultSentinelDBAgent."""
from unittest.mock import MagicMock, patch

import pytest

# pylint: disable=import-error
from vault_sentinel_db_agent import VaultSentinelDBAgent


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
    agent = VaultSentinelDBAgent()
    # Patch chat_client and Session
    agent.chat_client = MagicMock()
    agent.chat_client.chat.completions.create.return_value = MagicMock(
        choices=[MagicMock(message=MagicMock(content="SELECT * FROM items"))]
    )
    mock_session = MagicMock()
    mock_result = MagicMock()
    mock_result.fetchall.return_value = [("item1", "stat1")]
    mock_result.keys.return_value = ["name", "stat"]
    mock_session.execute.return_value = mock_result
    agent.Session = MagicMock(return_value=mock_session)

    with patch("builtins.open", MagicMock()), patch("json.dumps", MagicMock()):
        result = agent.process_query(get_valid_query())
        assert result["status"] == "success"
        assert "data" in result
        assert "sql" in result


def test_process_query_invalid_query():
    """Test processing of an invalid query."""
    agent = VaultSentinelDBAgent()
    invalid_query = {"intent": None}
    with pytest.raises(ValueError):
        agent.process_query(invalid_query)
