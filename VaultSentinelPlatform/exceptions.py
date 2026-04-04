"""Platform-level business exception hierarchy for Vault Sentinel."""

from __future__ import annotations

from typing import Any, Mapping


class PlatformError(Exception):
    """Base class for all Vault Sentinel platform failures."""

    def __init__(self, message: str, *, details: Mapping[str, Any] | None = None) -> None:
        super().__init__(message)
        self.details = dict(details or {})


class DomainError(PlatformError):
    """Base class for domain and business-rule failures."""


class BusinessRuleViolationError(DomainError, ValueError):
    """Raised when a requested operation violates a business rule or domain contract."""


class QueryValidationError(BusinessRuleViolationError):
    """Raised when an inbound query fails schema or semantic validation."""


class DependencyUnavailableError(DomainError, RuntimeError):
    """Raised when a required platform dependency is unavailable or not initialized."""


class ConfigurationError(DomainError):
    """Raised when required application configuration is missing or invalid."""


__all__ = [
    "PlatformError",
    "DomainError",
    "BusinessRuleViolationError",
    "QueryValidationError",
    "DependencyUnavailableError",
    "ConfigurationError",
]
