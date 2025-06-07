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
import requests

import azure.functions as func
from azure.functions.decorators import FunctionApp
from azure.data.tables import TableServiceClient
from azure.core.exceptions import ResourceExistsError
from vault_assistant import VaultAssistant
from helpers import retry_request

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

@app.route(route="assistant/init", methods=["POST"], auth_level=func.AuthLevel.ANONYMOUS)
def assistant_init(req: func.HttpRequest) -> func.HttpResponse:
    """Initializes the assistant by authenticating the user and fetching their Destiny 2 character summary."""
    logging.info("[assistant/init] POST request received.")
    try:
        access_token = req.get_json().get("access_token")
        if not access_token:
            return func.HttpResponse("Missing access_token", status_code=400)
    except ValueError:
        return func.HttpResponse("Invalid JSON body", status_code=400)
    result, status = assistant.initialize_user(access_token)
    if not result:
        return func.HttpResponse("Failed to initialize user", status_code=status)
    logging.info("[assistant/init] Successfully initialized user.")
    return func.HttpResponse(json.dumps(result, indent=2), mimetype="application/json")


@app.route(route="", methods=["POST"], auth_level=func.AuthLevel.ANONYMOUS)
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


@app.route(route="auth", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def auth(req: func.HttpRequest) -> func.HttpResponse:
    """Handles Bungie OAuth callback and exchanges code for access and refresh tokens."""
    logging.info("[auth] GET request received.")
    code = req.params.get("code")
    if not code:
        logging.error("[auth] Missing OAuth 'code' parameter in request.")
        return func.HttpResponse("Missing OAuth 'code' parameter.", status_code=400)
    token_url = "https://www.bungie.net/platform/app/oauth/token/"
    payload = {
        "grant_type": "authorization_code",
        "code": code,
        "client_id": os.environ.get("BUNGIE_CLIENT_ID"),
        "client_secret": os.environ.get("BUNGIE_CLIENT_SECRET"),
        "redirect_uri": os.environ.get("BUNGIE_REDIRECT_URI"),
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    try:
        response = retry_request(
            requests.post, token_url, data=payload, headers=headers, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        token_data = response.json()
        logging.info("[auth] Successfully exchanged code for tokens.")
    except Exception as e:
        logging.error("[auth] Token exchange failed: %s", e)
        return func.HttpResponse("OAuth token exchange failed.", status_code=500)
    # Save token info to Azure Table Storage
    try:
        table_service = TableServiceClient.from_connection_string(
            STORAGE_CONNECTION_STRING)
        table_client = table_service.get_table_client(TABLE_NAME)
        try:
            table_client.create_table()
            logging.info("[auth] Created new table for VaultSessions.")
        except ResourceExistsError:
            logging.info("[auth] VaultSessions table already exists.")
        # Fetch the user's membershipId to store in token_entity
        membership_id_val = ""
        try:
            headers_profile = {
                "Authorization": f"Bearer {token_data.get('access_token', '')}",
                "X-API-Key": API_KEY
            }
            profile_url = f"{BUNGIE_API_BASE}/User/GetMembershipsForCurrentUser/"
            profile_resp = retry_request(
                requests.get, profile_url, headers=headers_profile, timeout=REQUEST_TIMEOUT)
            if profile_resp.ok:
                profile_data = profile_resp.json().get("Response", {})
                if profile_data.get("destinyMemberships"):
                    membership_id_val = profile_data["destinyMemberships"][0].get(
                        "membershipId", "")
                    logging.info(
                        "[auth] Retrieved membershipId: %s", membership_id_val)
        except Exception as e:
            logging.warning("[auth] Could not retrieve membershipId: %s", e)
        token_entity = {
            "PartitionKey": "AuthSession",
            "RowKey": "last",
            "AccessToken": token_data.get("access_token", ""),
            "RefreshToken": token_data.get("refresh_token", ""),
            "ExpiresIn": str(token_data.get("expires_in", "3600")),
            "membershipId": membership_id_val
        }
        table_client.upsert_entity(entity=token_entity)
        logging.info("[auth] Token data stored in table storage for session.")
    except Exception as e:
        logging.error("[auth] Failed to store token data: %s", e)
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
    logging.info("[auth] Responding with OAuth HTML content.")
    return func.HttpResponse(html_content, mimetype="text/html")


@app.route(route="vault", methods=["POST"], auth_level=func.AuthLevel.ANONYMOUS)
def vault(req: func.HttpRequest) -> func.HttpResponse:
    """Returns the user's Destiny 2 vault inventory items."""
    logging.info("[vault] POST request received.")
    try:
        data = req.get_json()
        access_token = data.get("access_token")
    except ValueError:
        access_token = None

    if not access_token:
        try:
            table_service = TableServiceClient.from_connection_string(
                STORAGE_CONNECTION_STRING)
            table_client = table_service.get_table_client(TABLE_NAME)
            entity = table_client.get_entity(
                partition_key="AuthSession", row_key="last")
            access_token = entity.get("AccessToken")
            logging.info(
                "[vault] Using fallback access token from Table Storage.")
        except Exception as e:
            logging.error(
                "[vault] Failed to retrieve token from Table Storage: %s", e)
            return func.HttpResponse("Missing access_token and no valid session found.", status_code=403)
    inventory, status = assistant.get_vault(access_token)
    if inventory is None:
        logging.error(
            "[vault] Failed to get vault inventory. Status: %d", status)
        return func.HttpResponse("Failed to get vault inventory", status_code=status)
    logging.info("[vault] Successfully returned vault inventory.")
    return func.HttpResponse(json.dumps(inventory, indent=2), mimetype="application/json")


@app.route(route="characters", methods=["POST"], auth_level=func.AuthLevel.ANONYMOUS)
def characters(req: func.HttpRequest) -> func.HttpResponse:
    """Returns the user's Destiny 2 character equipment data."""
    logging.info("[characters] POST request received.")
    try:
        data = req.get_json()
        access_token = data.get("access_token")
    except ValueError:
        access_token = None

    if not access_token:
        try:
            table_service = TableServiceClient.from_connection_string(
                STORAGE_CONNECTION_STRING)
            table_client = table_service.get_table_client(TABLE_NAME)
            entity = table_client.get_entity(
                partition_key="AuthSession", row_key="last")
            access_token = entity.get("AccessToken")
            logging.info(
                "[characters] Using fallback access token from Table Storage.")
        except Exception as e:
            logging.error(
                "[characters] Failed to retrieve token from Table Storage: %s", e)
            return func.HttpResponse("Missing access_token and no valid session found.", status_code=403)
    equipment, status = assistant.get_characters(access_token)
    if equipment is None:
        logging.error(
            "[characters] Failed to get character equipment. Status: %d", status)
        return func.HttpResponse("Failed to get character equipment", status_code=status)
    logging.info("[characters] Successfully returned character equipment.")
    return func.HttpResponse(json.dumps(equipment, indent=2), mimetype="application/json")


@app.route(route="manifest/item", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def manifest_item(req: func.HttpRequest) -> func.HttpResponse:
    """Returns the manifest definition for a given item hash."""
    logging.info("[manifest/item] GET request received.")
    item_hash = req.params.get("id")
    if not item_hash:
        logging.error("[manifest/item] Missing item hash in request.")
        return func.HttpResponse("Missing item hash", status_code=400)
    definition, status = assistant.get_manifest_item(item_hash)
    if definition is None:
        logging.error(
            "[manifest/item] Item not found in manifest. Status: %d", status)
        return func.HttpResponse("Item not found in manifest", status_code=status)
    logging.info("[manifest/item] Successfully returned manifest item.")
    return func.HttpResponse(json.dumps(definition, indent=2), mimetype="application/json")


@app.route(route="dim/backup", methods=["POST"], auth_level=func.AuthLevel.ANONYMOUS)
def dim_backup(req: func.HttpRequest) -> func.HttpResponse:
    """Uploads a DIM backup and stores it in blob storage with metadata."""
    logging.info("[dim/backup] POST request received.")
    try:
        body = req.get_json()
        membership_id = body.get("membership_id")
        dim_backup = body.get("dim_backup")
        if not membership_id or not dim_backup:
            return func.HttpResponse("Missing membership_id or dim_backup", status_code=400)
        result, status = assistant.save_dim_backup(membership_id, dim_backup)
        logging.info("[dim/backup] DIM backup saved successfully.")
        return func.HttpResponse(json.dumps(result, indent=2), mimetype="application/json", status_code=status)
    except Exception as e:
        logging.error("[dim/backup] Error: %s", e)
        return func.HttpResponse("Failed to save DIM backup", status_code=500)


@app.route(route="dim/list", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
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
        result, status = assistant.list_dim_backups(membership_id)
        logging.info("[dim/list] Successfully retrieved DIM backups.")
        return func.HttpResponse(json.dumps(result, indent=2), mimetype="application/json")
    except Exception as e:
        logging.error("[dim/list] Error: %s", e)
        return func.HttpResponse("Failed to list DIM backups", status_code=500)


@app.route(route="token/refresh", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
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


@app.route(route="static/{filename}", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def serve_static(req: func.HttpRequest) -> func.HttpResponse:
    """Serves static files from the 'static' directory based on the requested filename. Supports .html, .yaml, .yml, and plain text files."""
    filename = req.route_params.get("filename")
    file_path = os.path.join("static", filename)
    try:
        with open(file_path, "rb") as f:
            content = f.read()
        mimetype = "text/plain"
        if filename.endswith(".html"):
            mimetype = "text/html"
        elif filename.endswith(".yaml") or filename.endswith(".yml"):
            mimetype = "application/x-yaml"
        logging.info("[static/%s] Serving static file.", filename)
        return func.HttpResponse(body=content, mimetype=mimetype)
    except FileNotFoundError:
        logging.error("[static/%s] File not found.", filename)
        return func.HttpResponse("File not found", status_code=404)


@app.route(route="session", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def get_session(req: func.HttpRequest) -> func.HttpResponse:
    """Returns the current session information including access token and membership ID."""
    try:
        session_data = assistant.get_session()
        return func.HttpResponse(json.dumps(session_data, indent=2), mimetype="application/json")
    except Exception as e:
        logging.error("[session] Failed to get session data: %s", e)
        return func.HttpResponse("Failed to get session data.", status_code=500)


@app.route(route="vault/decoded", methods=["POST"], auth_level=func.AuthLevel.ANONYMOUS)
def vault_decoded(req: func.HttpRequest) -> func.HttpResponse:
    """Returns the decoded version of the user's Destiny 2 vault inventory."""
    logging.info("[vault/decoded] POST request received.")
    try:
        data = req.get_json()
        access_token = data.get("access_token")
    except ValueError:
        access_token = None

    if not access_token:
        try:
            table_service = TableServiceClient.from_connection_string(STORAGE_CONNECTION_STRING)
            table_client = table_service.get_table_client(TABLE_NAME)
            entity = table_client.get_entity(partition_key="AuthSession", row_key="last")
            access_token = entity.get("AccessToken")
            logging.info("[vault/decoded] Using fallback access token from Table Storage.")
        except Exception as e:
            logging.error("[vault/decoded] Failed to retrieve token: %s", e)
            return func.HttpResponse("Missing access_token and no valid session found.", status_code=403)

    try:
        result, status = assistant.decode_vault(access_token)
        return func.HttpResponse(json.dumps(result, indent=2), mimetype="application/json", status_code=status)
    except Exception as e:
        logging.error("[vault/decoded] Failed to decode vault: %s", e)
        return func.HttpResponse("Failed to decode vault.", status_code=500)


@app.route(route="characters/decoded", methods=["POST"], auth_level=func.AuthLevel.ANONYMOUS)
def characters_decoded(req: func.HttpRequest) -> func.HttpResponse:
    """Returns the decoded version of the user's Destiny 2 character equipment."""
    logging.info("[characters/decoded] POST request received.")
    try:
        data = req.get_json()
        access_token = data.get("access_token")
    except ValueError:
        access_token = None

    if not access_token:
        try:
            table_service = TableServiceClient.from_connection_string(STORAGE_CONNECTION_STRING)
            table_client = table_service.get_table_client(TABLE_NAME)
            entity = table_client.get_entity(partition_key="AuthSession", row_key="last")
            access_token = entity.get("AccessToken")
            logging.info("[characters/decoded] Using fallback access token from Table Storage.")
        except Exception as e:
            logging.error("[characters/decoded] Failed to retrieve token: %s", e)
            return func.HttpResponse("Missing access_token and no valid session found.", status_code=403)

    try:
        result, status = assistant.decode_characters(access_token)
        return func.HttpResponse(json.dumps(result, indent=2), mimetype="application/json", status_code=status)
    except Exception as e:
        logging.error("[characters/decoded] Failed to decode character equipment: %s", e)
        return func.HttpResponse("Failed to decode character equipment.", status_code=500)


@app.route(route="session/token", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def session_token(req: func.HttpRequest) -> func.HttpResponse:
    """Returns the current access token and membership ID."""
    try:
        result, status_code = assistant.get_session_token()
        return func.HttpResponse(json.dumps(result, indent=2), status_code=status_code, mimetype="application/json")
    except Exception as e:
        logging.error("[session/token] Failed to get session token: %s", e)
        return func.HttpResponse("Failed to get session token.", status_code=500)
