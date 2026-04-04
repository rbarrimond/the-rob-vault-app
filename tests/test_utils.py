# pylint: disable=import-error,no-name-in-module
"""Unit tests for shared Azure Functions utilities."""

from __future__ import annotations

import base64
import gzip
import json

import azure.functions as func
import pytest

from VaultSentinelPlatform.api.http_utils import (
    build_save_response,
    compute_refresh_schedule,
    compress_response_if_requested,
    decode_save_content,
    endpoint,
    json_http_response,
    parse_pagination_params,
)
from VaultSentinelPlatform.exceptions import DependencyUnavailableError


def make_request(
    *,
    params: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
) -> func.HttpRequest:
    """Build a lightweight HTTP request for utility tests."""
    return func.HttpRequest(
        method="GET",
        url="http://localhost/api/test",
        headers=headers or {},
        params=params or {},
        route_params={},
        body=b"",
    )


def test_json_http_response_returns_json_payload() -> None:
    """The JSON response helper should serialize the payload and preserve the status code."""
    response = json_http_response({"status": "ok"}, status_code=201, indent=2)

    assert response.status_code == 201
    assert response.mimetype == "application/json"
    assert json.loads(response.get_body().decode("utf-8")) == {"status": "ok"}


def test_compress_response_if_requested_gzips_payload() -> None:
    """The compression helper should gzip the response when requested by the client."""
    request = make_request(headers={"Accept-Encoding": "gzip, deflate"})

    response = compress_response_if_requested('{"status": "ok"}', request)

    assert response.headers["Content-Encoding"] == "gzip"
    assert gzip.decompress(response.get_body()).decode("utf-8") == '{"status": "ok"}'


def test_parse_pagination_params_reads_limit_and_offset() -> None:
    """Pagination parsing should coerce numeric query parameters."""
    request = make_request(params={"limit": "25", "offset": "5"})

    assert parse_pagination_params(request) == (25, 5)


def test_parse_pagination_params_raises_for_invalid_values() -> None:
    """Invalid pagination input should raise ValueError for the caller to translate."""
    request = make_request(params={"limit": "abc"})

    with pytest.raises(ValueError, match="Invalid limit or offset parameter"):
        parse_pagination_params(request)


def test_decode_save_content_supports_base64_and_utf8() -> None:
    """Save-content decoding should handle the supported payload encodings."""
    raw_text = "vault-data"
    encoded = base64.b64encode(raw_text.encode("utf-8")).decode("utf-8")

    assert decode_save_content(encoded, "base64") == b"vault-data"
    assert decode_save_content(raw_text, "utf-8") == b"vault-data"


def test_build_save_response_shapes_success_payload() -> None:
    """The save-response helper should normalize successful save output."""
    payload, status = build_save_response({"message": "Saved", "url": "https://example"}, 200, "vault.json")

    assert status == 200
    assert payload == {
        "message": "Saved",
        "blob": "vault.json",
        "url": "https://example",
    }


def test_compute_refresh_schedule_uses_default_and_disable_cases() -> None:
    """Refresh schedule computation should preserve the current timer semantics."""
    assert compute_refresh_schedule(None) == ("0 */30 * * * *", 30)
    assert compute_refresh_schedule("-1") == (None, None)


def test_endpoint_decorator_passes_through_http_response() -> None:
    """The endpoint decorator should preserve explicit HttpResponse results."""

    @endpoint()
    def handler(_req: func.HttpRequest) -> func.HttpResponse:
        return func.HttpResponse("ok", status_code=204)

    response = handler(make_request())

    assert response.status_code == 204
    assert response.get_body() == b"ok"


def test_endpoint_decorator_maps_value_error_to_json_bad_request() -> None:
    """The endpoint decorator should normalize ValueError into a JSON 400 response."""

    @endpoint()
    def handler(_req: func.HttpRequest) -> dict[str, str]:
        raise ValueError("bad input")

    response = handler(make_request())

    assert response.status_code == 400
    assert json.loads(response.get_body().decode("utf-8")) == {"error": "bad input"}


def test_endpoint_decorator_maps_dependency_error_to_503() -> None:
    """The endpoint decorator should expose dependency failures as service unavailable."""

    @endpoint()
    def handler(_req: func.HttpRequest) -> dict[str, str]:
        raise DependencyUnavailableError("storage unavailable")

    response = handler(make_request())

    assert response.status_code == 503
    assert json.loads(response.get_body().decode("utf-8")) == {"error": "storage unavailable"}


def test_endpoint_decorator_preserves_compressed_response_headers() -> None:
    """Decorator pass-through should keep gzip response headers untouched."""

    @endpoint()
    def handler(req: func.HttpRequest) -> func.HttpResponse:
        return compress_response_if_requested('{"status": "ok"}', req)

    response = handler(make_request(headers={"Accept-Encoding": "gzip"}))

    assert response.status_code == 200
    assert response.headers["Content-Encoding"] == "gzip"
    assert gzip.decompress(response.get_body()).decode("utf-8") == '{"status": "ok"}'
