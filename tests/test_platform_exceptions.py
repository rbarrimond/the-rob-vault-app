"""Unit tests for the Vault Sentinel platform exception hierarchy."""

# pylint: disable=import-error,protected-access
from VaultSentinelPlatform.exceptions import (
    BusinessRuleViolationError,
    DependencyUnavailableError,
    DomainError,
    QueryValidationError,
)


def test_query_validation_error_preserves_details() -> None:
    """Query validation failures should remain typed business-rule errors."""
    error = QueryValidationError("Query does not conform to schema.", details={"field": "intent"})

    assert isinstance(error, DomainError)
    assert isinstance(error, BusinessRuleViolationError)
    assert isinstance(error, ValueError)
    assert error.details == {"field": "intent"}


def test_dependency_unavailable_error_is_runtime_error() -> None:
    """Unavailable runtime dependencies should carry platform context."""
    error = DependencyUnavailableError("Database session not available", details={"dependency": "database"})

    assert isinstance(error, DomainError)
    assert isinstance(error, RuntimeError)
    assert error.details["dependency"] == "database"
