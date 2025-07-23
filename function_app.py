# pylint: disable=missing-module-docstring, missing-function-docstring, invalid-name, broad-except, line-too-long
# pylint: disable=unused-argument
"""
Azure Function App for Destiny 2 Vault Assistant

This module provides HTTP-triggered Azure Functions for initializing the assistant, handling authentication,
fetching Destiny 2 vault and character data, and accessing manifest items from the Bungie API.
"""

import os
import json
import logging

import azure.functions as func
from azure.functions.decorators import FunctionApp
from azure.data.tables import TableServiceClient
from vault_assistant import VaultAssistant

# Configure logging
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "DEBUG"),
    format="%(asctime)s %(levelname)s %(name)s %(message)s"
)

app = FunctionApp()

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
    """Health check endpoint for Azure monitoring."""
    return func.HttpResponse(json.dumps({"status": "ok"}), mimetype="application/json", status_code=200)

@app.route(route="auth", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def auth(req: func.HttpRequest) -> func.HttpResponse:
    """Handles Bungie OAuth callback and exchanges code for access and refresh tokens."""
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


@app.route(route="assistant/init", methods=["POST"], auth_level=func.AuthLevel.FUNCTION)
def assistant_init(req: func.HttpRequest) -> func.HttpResponse:
    """Initializes the assistant by authenticating the user and fetching their Destiny 2 character summary."""
    logging.info("[assistant/init] POST request received.")
    result, status = assistant.initialize_user()
    if not result:
        return func.HttpResponse("Failed to initialize user", status_code=status)
    logging.info("[assistant/init] Successfully initialized user.")
    return func.HttpResponse(json.dumps(result, indent=2), mimetype="application/json")


@app.route(route="", methods=["POST"], auth_level=func.AuthLevel.FUNCTION)
def main(req: func.HttpRequest) -> func.HttpResponse:
    """Main entry point for the Vault assistant. Accepts either an access_token or a vault_data_path."""
    logging.info("[main] POST request received.")
    try:
        body = req.get_json()
    except ValueError:
        logging.error("[main] Invalid JSON body in request.")
        return func.HttpResponse("Invalid JSON", status_code=400)
    access_token = body.get("access_token")
    vault_data_path = body.get("vault_data_path")
    result, status = assistant.main_entry(access_token, vault_data_path)
    if "error" in result:
        logging.error("[main] Error in main entry: %s", result["error"])
        return func.HttpResponse(result["error"], status_code=status)
    logging.info("[main] Successfully processed main entry.")
    return func.HttpResponse(
        json.dumps(result, indent=2),
        mimetype="application/json"
    )


@app.route(route="vault", methods=["GET"], auth_level=func.AuthLevel.FUNCTION)
def vault(req: func.HttpRequest) -> func.HttpResponse:
    """Returns the user's Destiny 2 vault inventory items."""
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
    """Returns the user's Destiny 2 character equipment data."""
    logging.info("[characters] GET request received.")
    equipment, status = assistant.get_characters()
    if equipment is None:
        logging.error(
            "[characters] Failed to get character equipment. Status: %d", status)
        return func.HttpResponse("Failed to get character equipment", status_code=status)
    logging.info("[characters] Successfully returned character equipment.")
    return func.HttpResponse(json.dumps(equipment, indent=2), mimetype="application/json")


@app.route(route="manifest/item", methods=["GET"], auth_level=func.AuthLevel.FUNCTION)
def manifest_item(req: func.HttpRequest) -> func.HttpResponse:
    """Returns the manifest definition for a given item definition and hash."""
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


@app.route(route="dim/backup", methods=["POST"], auth_level=func.AuthLevel.FUNCTION)
def dim_backup(req: func.HttpRequest) -> func.HttpResponse:
    """Uploads a DIM backup and stores it in blob storage with metadata."""
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
    """Lists available DIM backups stored in blob storage for the current membership ID."""
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


@app.route(route="token/refresh", methods=["GET"], auth_level=func.AuthLevel.FUNCTION)
def refresh_token(req: func.HttpRequest) -> func.HttpResponse:
    """Refreshes access token using the stored refresh token and updates table storage."""
    logging.info("[token/refresh] GET request received.")
    try:
        table_service = TableServiceClient.from_connection_string(
            STORAGE_CONNECTION_STRING)
        table_client = table_service.get_table_client(TABLE_NAME)
        entity = table_client.get_entity(
            partition_key="AuthSession", row_key="last")
        refresh_token_val = entity.get("RefreshToken")
        if not refresh_token_val:
            logging.warning(
                "[token/refresh] No refresh token found. Re-authentication required.")
            return func.HttpResponse("No refresh token found. Please re-authenticate.", status_code=403)
        token_data, _ = assistant.refresh_token(refresh_token_val)
        entity.update({
            "AccessToken": token_data.get("access_token", ""),
            "RefreshToken": token_data.get("refresh_token", ""),
            "ExpiresIn": str(token_data.get("expires_in", "3600"))
        })
        table_client.upsert_entity(entity=entity)
        logging.info("[token/refresh] Successfully refreshed token.")
        return func.HttpResponse(json.dumps({"access_token": token_data["access_token"]}), mimetype="application/json")
    except Exception as e:
        logging.error("Token refresh failed: %s", e)
        return func.HttpResponse("Failed to refresh token.", status_code=500)

@app.route(route="static/{filename}", methods=["GET"], auth_level=func.AuthLevel.FUNCTION)
def serve_static(req: func.HttpRequest) -> func.HttpResponse:
    """[DEPRECATED] This endpoint is deprecated and no longer serves static files. Use a dedicated static file host or CDN instead."""
    filename = req.route_params.get("filename")
    logging.warning("[static/%s] Deprecated endpoint called. Returning 410 Gone.", filename)
    return func.HttpResponse(
        "This endpoint is deprecated and no longer serves static files.",
        status_code=410,
        mimetype="text/plain"
    )


@app.route(route="session", methods=["GET"], auth_level=func.AuthLevel.FUNCTION)
def get_session(req: func.HttpRequest) -> func.HttpResponse:
    """Returns the current session information including access token and membership ID."""
    try:
        session_data = assistant.get_session()
        return func.HttpResponse(json.dumps(session_data, indent=2), mimetype="application/json")
    except Exception as e:
        logging.error("[session] Failed to get session data: %s", e)
        return func.HttpResponse("Failed to get session data.", status_code=500)


@app.route(route="vault/decoded", methods=["GET"], auth_level=func.AuthLevel.FUNCTION)
def vault_decoded(req: func.HttpRequest) -> func.HttpResponse:
    """Returns the decoded version of the user's Destiny 2 vault inventory."""
    logging.info("[vault/decoded] GET request received.")
    try:
        result, status = assistant.decode_vault()
        return func.HttpResponse(json.dumps(result, indent=2), mimetype="application/json", status_code=status)
    except Exception as e:
        logging.error("[vault/decoded] Failed to decode vault: %s", e)
        return func.HttpResponse("Failed to decode vault.", status_code=500)


@app.route(route="characters/decoded", methods=["GET"], auth_level=func.AuthLevel.FUNCTION)
def characters_decoded(req: func.HttpRequest) -> func.HttpResponse:
    """Returns the decoded version of the user's Destiny 2 character equipment."""
    logging.info("[characters/decoded] GET request received.")
    try:
        result, status = assistant.decode_characters()
        return func.HttpResponse(json.dumps(result, indent=2), mimetype="application/json", status_code=status)
    except Exception as e:
        logging.error(
            "[characters/decoded] Failed to decode character equipment: %s", e)
        return func.HttpResponse("Failed to decode character equipment.", status_code=500)


@app.route(route="session/token", methods=["GET"], auth_level=func.AuthLevel.FUNCTION)
def session_token(req: func.HttpRequest) -> func.HttpResponse:
    """Returns the current access token and membership ID."""
    try:
        result, status_code = assistant.get_session_token()
        return func.HttpResponse(json.dumps(result, indent=2), status_code=status_code, mimetype="application/json")
    except Exception as e:
        logging.error("[session/token] Failed to get session token: %s", e)
        return func.HttpResponse("Failed to get session token.", status_code=500)
