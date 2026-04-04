"""Shared utilities for the Azure Functions HTTP adapter."""

from __future__ import annotations

import base64
import binascii
import gzip
import json
import logging
from functools import wraps
from io import BytesIO
from typing import Any, Callable, Mapping

import azure.functions as func
import pyodbc

from VaultSentinelPlatform.exceptions import (
    BusinessRuleViolationError,
    ConfigurationError,
    DependencyUnavailableError,
    QueryValidationError,
)

LOGGER = logging.getLogger(__name__)

JSON_MIMETYPE = "application/json"
INVALID_PAGINATION_MESSAGE = "Invalid limit or offset parameter."

try:
    PYODBC_ERROR = pyodbc.Error  # pylint: disable=c-extension-no-member,invalid-name
except AttributeError:  # pragma: no cover
    class PyodbcRuntimeError(Exception):
        """Fallback pyodbc error type when the C extension cannot expose members."""

    PYODBC_ERROR = PyodbcRuntimeError  # pylint: disable=invalid-name


def json_http_response(
    payload: dict[str, Any] | list[Any],
    status_code: int = 200,
    *,
    indent: int | None = None,
) -> func.HttpResponse:
    """Return a JSON response using the shared JSON mimetype constant."""
    return func.HttpResponse(
        json.dumps(payload, indent=indent),
        status_code=status_code,
        mimetype=JSON_MIMETYPE,
    )


def decode_save_content(content: str | bytes, encoding: str | None) -> bytes:
    """Decode object-save payload content into bytes based on the declared encoding."""
    if encoding == "base64":
        try:
            return base64.b64decode(content)
        except (binascii.Error, TypeError) as exc:
            raise ValueError(f"Base64 decode failed: {exc}") from exc
    if encoding in {"utf-8", None}:
        return content.encode("utf-8") if isinstance(content, str) else content
    raise ValueError(f"Unsupported encoding: {encoding}")


def build_save_response(
    result: Mapping[str, str],
    status: int,
    filename: str,
) -> tuple[dict[str, str], int]:
    """Build the API payload returned by the object-save endpoint."""
    if status == 200:
        return {
            "message": result.get("message", "Object saved successfully."),
            "blob": result.get("blob", filename),
            "url": result.get("url", ""),
        }, 200
    if status == 400:
        return {
            "error": result.get(
                "error",
                "Bad request (missing fields or invalid content)",
            )
        }, 400
    return {
        "error": result.get(
            "error",
            "Internal server error (failed to save object)",
        )
    }, 500


def compute_refresh_schedule(
    refresh_env: str | None,
    default_refresh_minutes: int = 30,
) -> tuple[str | None, int | None]:
    """Compute cron schedule and interval minutes from the environment override."""
    if refresh_env is None or not refresh_env.strip():
        return f"0 */{default_refresh_minutes} * * * *", default_refresh_minutes
    try:
        interval = int(refresh_env.strip())
    except ValueError:
        LOGGER.warning(
            "Invalid VAULT_REFRESH_INTERVAL_MINUTES='%s'. Disabling timer.",
            refresh_env,
        )
        return None, None
    if interval < 0:
        LOGGER.info("Vault refresh timer disabled (interval %d).", interval)
        return None, None
    if interval == 0:
        LOGGER.warning("Interval 0 is not supported. Disabling timer.")
        return None, None
    if interval < 60:
        return f"0 */{interval} * * * *", interval
    hours = max(1, interval // 60)
    return f"0 0 */{hours} * * *", interval


def parse_pagination_params(req: func.HttpRequest) -> tuple[int | None, int]:
    """Parse optional limit and offset query parameters from a request."""
    try:
        limit_param = req.params.get("limit")
        offset_param = req.params.get("offset")
        limit = int(limit_param) if limit_param is not None else None
        offset = int(offset_param) if offset_param is not None else 0
    except (ValueError, TypeError) as exc:
        raise ValueError(INVALID_PAGINATION_MESSAGE) from exc
    return limit, offset


def compress_response_if_requested(
    data: str,
    req: func.HttpRequest,
    status_code: int = 200,
) -> func.HttpResponse:
    """Compress the response using gzip when the client requests it."""
    accept_encoding = req.headers.get("Accept-Encoding", "")
    compress_param = req.params.get("compress", "false").lower() == "true"
    if "gzip" in accept_encoding.lower() or compress_param:
        buffer = BytesIO()
        with gzip.GzipFile(fileobj=buffer, mode="wb") as gzip_file:
            gzip_file.write(data.encode("utf-8"))
        return func.HttpResponse(
            body=buffer.getvalue(),
            status_code=status_code,
            mimetype=JSON_MIMETYPE,
            headers={"Content-Encoding": "gzip"},
        )
    return func.HttpResponse(data, mimetype=JSON_MIMETYPE, status_code=status_code)


def endpoint(
    fn: Callable[..., Any] | None = None,
    *,
    response_kind: str = "json",
    logger_override: logging.Logger | None = None,
    bad_request_exceptions: tuple[type[BaseException], ...] = (
        ValueError,
        QueryValidationError,
        BusinessRuleViolationError,
        ConfigurationError,
    ),
    not_found_exceptions: tuple[type[BaseException], ...] = (KeyError,),
    service_unavailable_exceptions: tuple[type[BaseException], ...] = (
        DependencyUnavailableError,
    ),
    bad_request_status: int = 400,
    not_found_status: int = 404,
    service_unavailable_status: int = 503,
    error_status: int = 500,
) -> Callable[[Callable[..., Any]], Callable[..., Any]] | Callable[..., Any]:
    """Decorator to standardize lightweight endpoint logging and JSON error handling."""
    if response_kind != "json":
        raise ValueError(f"Unsupported response kind: {response_kind}")

    logger_instance = logger_override or LOGGER

    def decorator(inner_fn: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(inner_fn)
        def wrapper(*args: Any, **kwargs: Any) -> func.HttpResponse | Any:
            try:
                result = inner_fn(*args, **kwargs)
            except bad_request_exceptions as exc:
                logger_instance.warning("[%s] Bad request: %s", inner_fn.__name__, exc)
                return json_http_response({"error": str(exc)}, status_code=bad_request_status)
            except not_found_exceptions as exc:
                logger_instance.warning("[%s] Not found: %s", inner_fn.__name__, exc)
                return json_http_response({"error": str(exc)}, status_code=not_found_status)
            except service_unavailable_exceptions as exc:
                logger_instance.error("[%s] Dependency unavailable: %s", inner_fn.__name__, exc)
                return json_http_response(
                    {"error": str(exc)},
                    status_code=service_unavailable_status,
                )
            except Exception as exc:  # pylint: disable=broad-exception-caught
                logger_instance.error("[%s] Unhandled endpoint failure: %s", inner_fn.__name__, exc, exc_info=True)
                return json_http_response(
                    {"error": "Internal server error."},
                    status_code=error_status,
                )

            if isinstance(result, func.HttpResponse):
                return result
            return result

        return wrapper

    if fn is not None:
        return decorator(fn)
    return decorator


__all__ = [
    "PYODBC_ERROR",
    "JSON_MIMETYPE",
    "INVALID_PAGINATION_MESSAGE",
    "build_save_response",
    "compress_response_if_requested",
    "compute_refresh_schedule",
    "decode_save_content",
    "endpoint",
    "json_http_response",
    "parse_pagination_params",
]
