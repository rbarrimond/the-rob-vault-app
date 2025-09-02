# pylint: disable=missing-module-docstring, missing-function-docstring, invalid-name, broad-except, line-too-long
# pylint: disable=unused-argument
"""
Azure Function App for Destiny 2 Vault Assistant.

Exposes HTTP-triggered Azure Functions for:
- Health checks and diagnostics
- OAuth authentication and session management
- Fetching Destiny 2 vault and character data
- Decoding and accessing manifest items
- DIM backup management
- Querying the Vault Sentinel agent
All endpoints return JSON or HTML responses suitable for web and API clients.
"""

import json
import logging
import os
import platform
import sys
import types
import base64

import azure.functions as func
import psutil
from azure.data.tables import TableServiceClient

from vault_assistant import VaultAssistant

app = func.FunctionApp()

# Constants and configuration
BUNGIE_API_BASE = "https://www.bungie.net/Platform"
API_KEY = os.getenv("BUNGIE_API_KEY")
STORAGE_CONNECTION_STRING = os.getenv("AZURE_STORAGE_CONNECTION_STRING")
BLOB_CONTAINER = "vault-data"
TABLE_NAME = "VaultSessions"
REQUEST_TIMEOUT = 10  # seconds

manifest_cache = {}
assistant = VaultAssistant(
    api_key=API_KEY,
    storage_conn_str=STORAGE_CONNECTION_STRING,
    table_name=TABLE_NAME,
    blob_container=BLOB_CONTAINER,
    api_base=BUNGIE_API_BASE,
    timeout=REQUEST_TIMEOUT
)

# ----------------------
# Route Handler Functions
# ----------------------


@app.route(route="health", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def healthcheck(req: func.HttpRequest) -> func.HttpResponse:
    """
    Health check endpoint for Azure monitoring.
    Returns process diagnostics including Python version, platform, CPU, memory, and key environment variables.

    Args:
        req (func.HttpRequest): The HTTP request object.
    Returns:
        func.HttpResponse: JSON response with diagnostics or error.
    """
    try:
        process = psutil.Process()
        mem_info = process.memory_info()
        diagnostics = {
            "status": "ok",
            "python_version": sys.version,
            "platform": platform.platform(),
            "cpu_count": psutil.cpu_count(),
            "memory": {
                "rss": mem_info.rss,  # Resident Set Size in bytes
                "vms": mem_info.vms,  # Virtual Memory Size in bytes
            },
            "env": {
                "LOG_LEVEL": logging.getLevelName(logging.getLogger().getEffectiveLevel()),
                "BUNGIE_API_KEY": bool(os.getenv("BUNGIE_API_KEY")),
                "AZURE_STORAGE_CONNECTION_STRING": bool(os.getenv("AZURE_STORAGE_CONNECTION_STRING")),
            }
        }
        return func.HttpResponse(json.dumps(diagnostics, indent=2), mimetype="application/json", status_code=200)
    except Exception as e:
        return func.HttpResponse(json.dumps({"status": "error", "error": str(e)}), mimetype="application/json", status_code=500)


# --- Authentication & Session ---


@app.route(route="auth", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def auth(req: func.HttpRequest) -> func.HttpResponse:
    """
    Handles Bungie OAuth callback.
    Exchanges the authorization code for access and refresh tokens, stores the session, and returns an HTML page to initialize the assistant.

    Args:
        req (func.HttpRequest): The HTTP request object.
    Returns:
        func.HttpResponse: HTML response for OAuth completion.
    """
    logging.info("[auth] GET request received.")
    code = req.params.get("code")
    if not code:
        logging.error("[auth] Missing OAuth 'code' parameter in request.")
        return func.HttpResponse("Missing OAuth 'code' parameter.", status_code=400)
    try:
        token_data = assistant.exchange_code_for_token(code)
        logging.info(
            "[auth] Successfully exchanged code for tokens and stored session.")
    except Exception as e:
        logging.error("[auth] Token exchange failed: %s", e)
        return func.HttpResponse("OAuth token exchange failed.", status_code=500)
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Authorization Complete</title>
        <script>
            async function sendToken() {{
                const response = await fetch('/api/assistant/init', {{
                    method: 'POST',
                    headers: {{
                        'Content-Type': 'application/json'
                    }},
                    body: JSON.stringify({{ access_token: "{token_data['access_token']}" }})
                }});
                const result = await response.text();
                document.getElementById('result').textContent = result;
            }}
            window.onload = sendToken;
        </script>
    </head>
    <body>
        <h1>Authorization Complete</h1>
        <p>Initializing assistant…</p>
        <pre id="result">Please wait...</pre>
    </body>
    </html>
    """
    logging.info("[auth] Responding with OAuth HTML content and token data.")
    return func.HttpResponse(html_content, mimetype="text/html")


@app.route(route="assistant/init", methods=["POST"], auth_level=func.AuthLevel.ANONYMOUS)
def assistant_init(req: func.HttpRequest) -> func.HttpResponse:
    """
    Initializes the assistant for the user.
    Authenticates the user and fetches their Destiny 2 character summary.

    Args:
        req (func.HttpRequest): The HTTP request object.
    Returns:
        func.HttpResponse: JSON response with user summary or error.
    """
    logging.info("[assistant/init] POST request received.")
    result, status = assistant.initialize_user()
    if not result:
        return func.HttpResponse("Failed to initialize user", status_code=status)
    logging.info("[assistant/init] Successfully initialized user.")
    return func.HttpResponse(json.dumps(result, indent=2), mimetype="application/json")


@app.route(route="session", methods=["GET"], auth_level=func.AuthLevel.FUNCTION)
def get_session(req: func.HttpRequest) -> func.HttpResponse:
    """
    Returns the current session information including access token and membership ID.

    Args:
        req (func.HttpRequest): The HTTP request object.
    Returns:
        func.HttpResponse: JSON response with session info or error.
    """
    try:
        session_data = assistant.get_session()
        return func.HttpResponse(json.dumps(session_data, indent=2), mimetype="application/json")
    except Exception as e:
        logging.error("[session] Failed to get session data: %s", e)
        return func.HttpResponse("Failed to get session data.", status_code=500)


@app.route(route="session/token", methods=["GET"], auth_level=func.AuthLevel.FUNCTION)
def session_token(req: func.HttpRequest) -> func.HttpResponse:
    """
    Returns the current access token and membership ID.

    Args:
        req (func.HttpRequest): The HTTP request object.
    Returns:
        func.HttpResponse: JSON response with token info or error.
    """
    try:
        result, status_code = assistant.get_session_token()
        return func.HttpResponse(json.dumps(result, indent=2), status_code=status_code, mimetype="application/json")
    except Exception as e:
        logging.error("[session/token] Failed to get session token: %s", e)
        return func.HttpResponse("Failed to get session token.", status_code=500)


@app.route(route="token/refresh", methods=["GET"], auth_level=func.AuthLevel.FUNCTION)
def refresh_token(req: func.HttpRequest) -> func.HttpResponse:
    """
    Refreshes the access token using the stored refresh token via the assistant.
    Returns the new access token.

    Args:
        req (func.HttpRequest): The HTTP request object.
    Returns:
        func.HttpResponse: JSON response with new access token or error.
    """
    logging.info("[token/refresh] GET request received.")
    try:
        session = assistant.get_session()
        refresh_token_val = session.get("RefreshToken")
        if not refresh_token_val:
            logging.warning("[token/refresh] No refresh token found. Re-authentication required.")
            return func.HttpResponse("No refresh token found. Please re-authenticate.", status_code=403)
        token_data, _ = assistant.refresh_token(refresh_token_val)
        logging.info("[token/refresh] Successfully refreshed token.")
        return func.HttpResponse(json.dumps({"access_token": token_data["access_token"]}), mimetype="application/json")
    except Exception as e:
        logging.error("Token refresh failed: %s", e)
        return func.HttpResponse("Failed to refresh token.", status_code=500)


# --- Main Functionality Endpoints ---

@app.route(route="vault", methods=["GET"], auth_level=func.AuthLevel.FUNCTION)
def vault(req: func.HttpRequest) -> func.HttpResponse:
    """
    Returns the user's Destiny 2 vault inventory items.

    Args:
        req (func.HttpRequest): The HTTP request object. Accepts 'limit' and 'offset' query params for pagination.
    Returns:
        func.HttpResponse: JSON response with inventory items or error.
    """
    logging.info("[vault] GET request received.")
    try:
        limit = req.params.get("limit")
        offset = req.params.get("offset")
        limit = int(limit) if limit is not None else None
        offset = int(offset) if offset is not None else 0
    except Exception:
        return func.HttpResponse("Invalid limit or offset parameter.", status_code=400)
    inventory, status = assistant.get_vault()
    if inventory is None:
        logging.error(
            "[vault] Failed to get vault inventory. Status: %d", status)
        return func.HttpResponse("Failed to get vault inventory", status_code=status)
    # Apply pagination
    paged_inventory = inventory[offset:offset+limit] if limit is not None else inventory[offset:]
    logging.info("[vault] Successfully returned vault inventory.")
    return func.HttpResponse(json.dumps(paged_inventory, indent=2), mimetype="application/json")


@app.route(route="characters", methods=["GET"], auth_level=func.AuthLevel.FUNCTION)
def characters(req: func.HttpRequest) -> func.HttpResponse:
    """
    Returns the user's Destiny 2 character equipment data.

    Args:
        req (func.HttpRequest): The HTTP request object. Accepts 'limit' and 'offset' query params for pagination.
    Returns:
        func.HttpResponse: JSON response with character equipment or error.
    """
    logging.info("[characters] GET request received.")
    try:
        limit = req.params.get("limit")
        offset = req.params.get("offset")
        limit = int(limit) if limit is not None else None
        offset = int(offset) if offset is not None else 0
    except Exception:
        return func.HttpResponse("Invalid limit or offset parameter.", status_code=400)
    equipment, status = assistant.get_characters()
    if equipment is None:
        logging.error(
            "[characters] Failed to get character equipment. Status: %d", status)
        return func.HttpResponse("Failed to get character equipment", status_code=status)
    # Apply pagination per character
    if isinstance(equipment, dict):
        paged_equipment = {}
        for char_id, char_data in equipment.items():
            items = char_data.get("items", [])
            paged_items = items[offset:offset+limit] if limit is not None else items[offset:]
            paged_equipment[char_id] = {**char_data, "items": paged_items}
    else:
        paged_equipment = equipment
    logging.info("[characters] Successfully returned character equipment.")
    return func.HttpResponse(json.dumps(paged_equipment, indent=2), mimetype="application/json")


@app.route(route="vault/decoded", methods=["GET"], auth_level=func.AuthLevel.FUNCTION)
def vault_decoded(req: func.HttpRequest) -> func.HttpResponse:
    """
    Returns the decoded version of the user's Destiny 2 vault inventory.
    Optional query param: includePerks (bool), limit, offset.

    Args:
        req (func.HttpRequest): The HTTP request object.
    Returns:
        func.HttpResponse: JSON response with decoded inventory or error.
    """
    logging.info("[vault/decoded] GET request received.")
    include_perks = req.params.get("includePerks", "false").lower() == "true"
    try:
        limit = req.params.get("limit")
        offset = req.params.get("offset")
        limit = int(limit) if limit is not None else None
        offset = int(offset) if offset is not None else 0
    except Exception:
        return func.HttpResponse("Invalid limit or offset parameter.", status_code=400)
    try:
        result, status = assistant.decode_vault(include_perks=include_perks, limit=limit, offset=offset)
        return func.HttpResponse(json.dumps(result, indent=2), mimetype="application/json", status_code=status)
    except Exception as e:
        logging.error("[vault/decoded] Failed to decode vault: %s", e)
        return func.HttpResponse("Failed to decode vault.", status_code=500)


@app.route(route="characters/decoded", methods=["GET"], auth_level=func.AuthLevel.FUNCTION)
def characters_decoded(req: func.HttpRequest) -> func.HttpResponse:
    """
    Returns the decoded version of the user's Destiny 2 character equipment.
    Optional query param: includePerks (bool), limit, offset.

    Args:
        req (func.HttpRequest): The HTTP request object.
    Returns:
        func.HttpResponse: JSON response with decoded equipment or error.
    """
    logging.info("[characters/decoded] GET request received.")
    include_perks = req.params.get("includePerks", "false").lower() == "true"
    try:
        limit = req.params.get("limit")
        offset = req.params.get("offset")
        limit = int(limit) if limit is not None else None
        offset = int(offset) if offset is not None else 0
    except Exception:
        return func.HttpResponse("Invalid limit or offset parameter.", status_code=400)
    try:
        result, status = assistant.decode_characters(include_perks=include_perks, limit=limit, offset=offset)
        return func.HttpResponse(json.dumps(result, indent=2), mimetype="application/json", status_code=status)
    except Exception as e:
        logging.error("[characters/decoded] Failed to decode character equipment: %s", e)
        return func.HttpResponse("Failed to decode character equipment.", status_code=500)


@app.route(route="manifest/item", methods=["GET"], auth_level=func.AuthLevel.FUNCTION)
def manifest_item(req: func.HttpRequest) -> func.HttpResponse:
    """
    Returns the manifest definition for a given Destiny 2 item.
    Requires 'hash' query parameter and optional 'type'.

    Args:
        req (func.HttpRequest): The HTTP request object.
    Returns:
        func.HttpResponse: JSON response with manifest item or error.
    """
    logging.info("[manifest/item] GET request received.")
    hash_val = req.params.get("hash")
    if not hash_val:
        logging.error("[manifest/item] Missing 'hash' in request.")
        return func.HttpResponse("Missing 'hash' query parameter.", status_code=400)
    try:
        hash_str = str(hash_val)
        int(hash_val)
    except Exception:
        return func.HttpResponse("'hash' must be an integer.", status_code=400)
    type_val = req.params.get("type")
    definition_data, status = assistant.get_manifest_item(hash_str, type_val)
    if definition_data is None or (isinstance(definition_data, dict) and definition_data.get("error")):
        logging.error("[manifest/item] Item not found in manifest. Status: %d", status)
        return func.HttpResponse("Item not found in manifest", status_code=status)
    logging.info("[manifest/item] Successfully returned manifest item.")
    return func.HttpResponse(json.dumps(definition_data, indent=2), mimetype="application/json")


# --- DIM Backup and Data Management Endpoints ---

@app.route(route="dim/backup", methods=["POST"], auth_level=func.AuthLevel.FUNCTION)
def dim_backup(req: func.HttpRequest) -> func.HttpResponse:
    """
    Uploads a DIM backup and stores it in blob storage with metadata.
    Expects 'membership_id' and 'dim_backup' in the POST body.

    Args:
        req (func.HttpRequest): The HTTP request object.
    Returns:
        func.HttpResponse: JSON response with backup result or error.
    """
    logging.info("[dim/backup] POST request received.")
    try:
        body = req.get_json()
        membership_id = body.get("membership_id")
        dim_backup_data = body.get("dim_backup")
        if not membership_id or not dim_backup_data:
            return func.HttpResponse("Missing membership_id or dim_backup", status_code=400)
        result, status = assistant.save_dim_backup(
            membership_id, dim_backup_data)
        logging.info("[dim/backup] DIM backup saved successfully.")
        return func.HttpResponse(json.dumps(result, indent=2), mimetype="application/json", status_code=status)
    except Exception as e:
        logging.error("[dim/backup] Error: %s", e)
        return func.HttpResponse("Failed to save DIM backup", status_code=500)


@app.route(route="dim/list", methods=["GET"], auth_level=func.AuthLevel.FUNCTION)
def dim_list(req: func.HttpRequest) -> func.HttpResponse:
    """
    Lists available DIM backups stored in blob storage for the current membership ID.

    Args:
        req (func.HttpRequest): The HTTP request object.
    Returns:
        func.HttpResponse: JSON response with backup list or error.
    """
    logging.info("[dim/list] GET request received.")
    try:
        table_service = TableServiceClient.from_connection_string(
            STORAGE_CONNECTION_STRING)
        table_client = table_service.get_table_client(TABLE_NAME)
        entity = table_client.get_entity(
            partition_key="AuthSession", row_key="last")
        membership_id = entity.get("membershipId")
        if not membership_id:
            logging.warning("[dim/list] No stored membership ID found.")
            return func.HttpResponse("No stored membership ID found.", status_code=400)
        result, _ = assistant.list_dim_backups(membership_id)
        logging.info("[dim/list] Successfully retrieved DIM backups.")
        return func.HttpResponse(json.dumps(result, indent=2), mimetype="application/json")
    except Exception as e:
        logging.error("[dim/list] Error: %s", e)
        return func.HttpResponse("Failed to list DIM backups", status_code=500)


@app.route(route="query", methods=["POST"], auth_level=func.AuthLevel.FUNCTION)
def query_agent(req: func.HttpRequest) -> func.HttpResponse:
    """
    Accepts a JSON query conforming to the Vault Sentinel schema and returns the agent's response.

    Args:
        req (func.HttpRequest): The HTTP request object. Expects JSON body with query.
    Returns:
        func.HttpResponse: JSON response with agent result or error.
    """
    logging.info("[query] POST request received.")
    try:
        query = req.get_json()
    except Exception as e:
        logging.error("[query] Invalid JSON: %s", e)
        return func.HttpResponse(json.dumps({"error": "Invalid JSON"}), status_code=400, mimetype="application/json")
    try:
        result = assistant.process_query(query)
        return func.HttpResponse(json.dumps(result, indent=2), mimetype="application/json", status_code=200)
    except Exception as e:
        logging.error("[query] Agent error: %s", e)
        return func.HttpResponse(json.dumps({"error": str(e)}), status_code=400, mimetype="application/json")


@app.route(route="static/{filename}", methods=["GET"], auth_level=func.AuthLevel.FUNCTION)
def serve_static(req: func.HttpRequest) -> func.HttpResponse:
    """
    [DEPRECATED] This endpoint is deprecated and no longer serves static files.
    Use a dedicated static file host or CDN instead.

    Args:
        req (func.HttpRequest): The HTTP request object.
    Returns:
        func.HttpResponse: 410 Gone response.
    """
    filename = req.route_params.get("filename")
    logging.warning(
        "[static/%s] Deprecated endpoint called. Returning 410 Gone.", filename)
    return func.HttpResponse(
        "This endpoint is deprecated and no longer serves static files.",
        status_code=410,
        mimetype="text/plain"
    )


@app.route(route="save", methods=["POST"], auth_level=func.AuthLevel.FUNCTION)
def save_object(req: func.HttpRequest) -> func.HttpResponse:

    """
    Save an object or file to Azure Blob Storage.

    Expects a JSON POST body with:
        - filename: Name of the file to save (string, required)
        - content_type: MIME type of the file (string, optional)
        - content: File content as a string or base64-encoded string (required)
        - encoding: Encoding of the content ("base64" or "utf-8", optional)

    Returns a JSON response with:
        - message: Success message
        - blob: Saved filename
        - url: Blob URL
    On error, returns a JSON response with an error message and appropriate status code.
    """
    logging.info("[save] POST request received.")
    try:
        body = req.get_json()
    except Exception:
        body = None
    if not body:
        return func.HttpResponse(json.dumps({"error": "Missing request body"}), status_code=400, mimetype="application/json")

    # Validate required fields
    filename = body.get("filename")
    content_type = body.get("content_type")
    content = body.get("content")
    encoding = body.get("encoding")

    if not filename or not content:
        return func.HttpResponse(json.dumps({"error": "Missing filename or content in MIME object."}), status_code=400, mimetype="application/json")

    # Handle encoding
    if encoding == "base64":
        try:
            content = base64.b64decode(content)
        except Exception as e:
            return func.HttpResponse(json.dumps({"error": f"Base64 decode failed: {e}"}), status_code=400, mimetype="application/json")
    elif encoding == "utf-8" or encoding is None:
        if isinstance(content, str):
            content = content.encode("utf-8")
    else:
        return func.HttpResponse(json.dumps({"error": f"Unsupported encoding: {encoding}"}), status_code=400, mimetype="application/json")

    # Create MIME-like object
    mime_obj = types.SimpleNamespace(
        filename=filename,
        content_type=content_type or "application/octet-stream",
        content=content
    )
    result, status = assistant.save_object(mime_obj)

    # Format response per OpenAPI spec
    if status == 200:
        response = {
            "message": result.get("message", "Object saved successfully."),
            "blob": result.get("blob", filename),
            "url": result.get("url", "")
        }
        return func.HttpResponse(json.dumps(response), status_code=200, mimetype="application/json")
    elif status == 400:
        response = {"error": result.get("error", "Bad request (missing fields or invalid content)")}
        return func.HttpResponse(json.dumps(response), status_code=400, mimetype="application/json")
    else:
        response = {"error": result.get("error", "Internal server error (failed to save object)")}
        return func.HttpResponse(json.dumps(response), status_code=500, mimetype="application/json")
