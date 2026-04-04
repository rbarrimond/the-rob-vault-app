"""HTTP adapter utilities for the Vault Sentinel Azure Functions surface."""

from .http_utils import (
    INVALID_PAGINATION_MESSAGE,
    JSON_MIMETYPE,
    PYODBC_ERROR,
    build_save_response,
    compress_response_if_requested,
    compute_refresh_schedule,
    decode_save_content,
    endpoint,
    json_http_response,
    parse_pagination_params,
)

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
