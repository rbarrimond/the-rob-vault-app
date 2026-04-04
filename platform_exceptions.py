"""Compatibility shim for platform exception exports."""

from VaultSentinelPlatform.exceptions import (
    BusinessRuleViolationError,
    ConfigurationError,
    DependencyUnavailableError,
    DomainError,
    PlatformError,
    QueryValidationError,
)

__all__ = [
    "PlatformError",
    "DomainError",
    "BusinessRuleViolationError",
    "QueryValidationError",
    "DependencyUnavailableError",
    "ConfigurationError",
]
