# pylint: disable=import-error,no-name-in-module
"""Regression tests for the `/api/query` endpoint exception contract."""

from __future__ import annotations

import json
from unittest.mock import patch

import azure.functions as func

import function_app
from VaultSentinelPlatform.exceptions import DependencyUnavailableError, QueryValidationError


def make_request(payload: dict) -> func.HttpRequest:
    """Build a lightweight POST request for the query endpoint."""
    return func.HttpRequest(
        method="POST",
        url="http://localhost/api/query",
        headers={"Content-Type": "application/json"},
        params={},
        route_params={},
        body=json.dumps(payload).encode("utf-8"),
    )


def test_query_agent_maps_dependency_unavailable_to_503() -> None:
    """Dependency failures should reach `@endpoint()` and become HTTP 503 responses."""
    with patch.object(
        function_app.assistant,
        "process_query",
        side_effect=DependencyUnavailableError("database temporarily unavailable"),
    ):
        response = function_app.query_agent(make_request({"intent": "status"}))

    assert response.status_code == 503
    assert json.loads(response.get_body().decode("utf-8")) == {
        "error": "database temporarily unavailable"
    }


def test_query_agent_maps_query_validation_error_to_400() -> None:
    """Business validation failures should remain client-visible bad requests."""
    with patch.object(
        function_app.assistant,
        "process_query",
        side_effect=QueryValidationError("Missing required key: filters"),
    ):
        response = function_app.query_agent(make_request({"intent": "status"}))

    assert response.status_code == 400
    assert json.loads(response.get_body().decode("utf-8")) == {
        "error": "Missing required key: filters"
    }
