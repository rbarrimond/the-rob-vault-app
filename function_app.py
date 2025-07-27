# pylint: disable=missing-module-docstring, missing-function-docstring, invalid-name, broad-except, line-too-long
# pylint: disable=unused-argument
"""
Azure Function App for Destiny 2 Vault Assistant

This module provides HTTP-triggered Azure Functions for initializing the assistant, handling authentication,
fetching Destiny 2 vault and character data, and accessing manifest items from the Bungie API.
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

# Configure logging
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "DEBUG"),
    format="%(asctime)s %(levelname)s %(name)s %(message)s"
)

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
    manifest_cache=manifest_cache,
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
                "LOG_LEVEL": logging.getLogger().getEffectiveLevel(),
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
    """
    logging.info("[token/refresh] GET request received.")
    try:
        session = assistant.get_session()
        refresh_token_val = session.get("RefreshToken")
        if not refresh_token_val:
            logging.warning(
                "[token/refresh] No refresh token found. Re-authentication required.")
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
    """
    logging.info("[vault] GET request received.")
    inventory, status = assistant.get_vault()
    if inventory is None:
        logging.error(
            "[vault] Failed to get vault inventory. Status: %d", status)
        return func.HttpResponse("Failed to get vault inventory", status_code=status)
    logging.info("[vault] Successfully returned vault inventory.")
    return func.HttpResponse(json.dumps(inventory, indent=2), mimetype="application/json")


@app.route(route="characters", methods=["GET"], auth_level=func.AuthLevel.FUNCTION)
def characters(req: func.HttpRequest) -> func.HttpResponse:
    """
    Returns the user's Destiny 2 character equipment data.
    """
    logging.info("[characters] GET request received.")
    equipment, status = assistant.get_characters()
    if equipment is None:
        logging.error(
            "[characters] Failed to get character equipment. Status: %d", status)
        return func.HttpResponse("Failed to get character equipment", status_code=status)
    logging.info("[characters] Successfully returned character equipment.")
    return func.HttpResponse(json.dumps(equipment, indent=2), mimetype="application/json")



@app.route(route="vault/decoded", methods=["GET"], auth_level=func.AuthLevel.FUNCTION)
def vault_decoded(req: func.HttpRequest) -> func.HttpResponse:
    """
    Returns the decoded version of the user's Destiny 2 vault inventory.
    Optional query param: includePerks (bool)
    """
    logging.info("[vault/decoded] GET request received.")
    include_perks = req.params.get("includePerks", "false").lower() == "true"
    try:
        result, status = assistant.decode_vault(include_perks=include_perks)
        return func.HttpResponse(json.dumps(result, indent=2), mimetype="application/json", status_code=status)
    except Exception as e:
        logging.error("[vault/decoded] Failed to decode vault: %s", e)
        return func.HttpResponse("Failed to decode vault.", status_code=500)



@app.route(route="characters/decoded", methods=["GET"], auth_level=func.AuthLevel.FUNCTION)
def characters_decoded(req: func.HttpRequest) -> func.HttpResponse:
    """
    Returns the decoded version of the user's Destiny 2 character equipment.
    Optional query param: includePerks (bool)
    """
    logging.info("[characters/decoded] GET request received.")
    include_perks = req.params.get("includePerks", "false").lower() == "true"
    try:
        result, status = assistant.decode_characters(include_perks=include_perks)
        return func.HttpResponse(json.dumps(result, indent=2), mimetype="application/json", status_code=status)
    except Exception as e:
        logging.error("[characters/decoded] Failed to decode character equipment: %s", e)
        return func.HttpResponse("Failed to decode character equipment.", status_code=500)


@app.route(route="manifest/item", methods=["GET"], auth_level=func.AuthLevel.FUNCTION)
def manifest_item(req: func.HttpRequest) -> func.HttpResponse:
    """
    Returns the manifest definition for a given Destiny 2 item.
    Requires 'definition' and 'hash' query parameters.
    """
    logging.info("[manifest/item] GET request received.")
    definition = req.params.get("definition")
    hash_val = req.params.get("hash")
    if not definition or not hash_val:
        logging.error(
            "[manifest/item] Missing 'definition' or 'hash' in request.")
        return func.HttpResponse("Missing 'definition' or 'hash' query parameter.", status_code=400)
    try:
        hash_str = str(hash_val)
        # Optionally, validate hash is integer
        int(hash_val)
    except Exception:
        return func.HttpResponse("'hash' must be an integer.", status_code=400)
    # The assistant expects item_hash as string
    definition_data, status = assistant.get_manifest_item(hash_str)
    if definition_data is None:
        logging.error(
            "[manifest/item] Item not found in manifest. Status: %d", status)
        return func.HttpResponse("Item not found in manifest", status_code=status)
    logging.info("[manifest/item] Successfully returned manifest item.")
    return func.HttpResponse(json.dumps(definition_data, indent=2), mimetype="application/json")


# --- DIM Backup and Data Management Endpoints ---

@app.route(route="dim/backup", methods=["POST"], auth_level=func.AuthLevel.FUNCTION)
def dim_backup(req: func.HttpRequest) -> func.HttpResponse:
    """
    Uploads a DIM backup and stores it in blob storage with metadata.
    Expects 'membership_id' and 'dim_backup' in the POST body.
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


# --- General Utility & New Features ---


@app.route(route="static/{filename}", methods=["GET"], auth_level=func.AuthLevel.FUNCTION)
def serve_static(req: func.HttpRequest) -> func.HttpResponse:
    """
    [DEPRECATED] This endpoint is deprecated and no longer serves static files.
    Use a dedicated static file host or CDN instead.
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
    Save an object or file to storage using the assistant's save_object method.
    Accepts JSON with base64 or string content, or multipart form-data (future).
    """
    logging.info("[save] POST request received.")
    try:
        body = req.get_json()
    except Exception:
        body = None
    if not body:
        return func.HttpResponse(json.dumps({"error": "Missing request body"}), status_code=400, mimetype="application/json")

    filename = body.get("filename") or body.get("name") or "uploaded-object"
    content_type = body.get("content_type") or body.get(
        "mimetype") or "application/octet-stream"
    content = body.get("content")
    if content is None:
        return func.HttpResponse(json.dumps({"error": "Missing content in request"}), status_code=400, mimetype="application/json")

    # If content looks like base64, decode it
    if body.get("encoding") == "base64":
        try:
            content = base64.b64decode(content)
        except Exception as e:
            return func.HttpResponse(json.dumps({"error": f"Base64 decode failed: {e}"}), status_code=400, mimetype="application/json")
    elif isinstance(content, str):
        content = content.encode("utf-8")

    # Create a simple MIME-like object
    mime_obj = types.SimpleNamespace(
        filename=filename, content_type=content_type, content=content)
    result, status = assistant.save_object(mime_obj)
    return func.HttpResponse(json.dumps(result), status_code=status, mimetype="application/json")
