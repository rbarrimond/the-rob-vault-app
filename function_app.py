"""
Azure Function App for Destiny 2 Vault Assistant

This module provides HTTP-triggered Azure Functions for initializing the assistant, handling authentication,
fetching Destiny 2 vault and character data, and accessing manifest items from the Bungie API.
"""

import os
import json
import logging
import time
import datetime
import hashlib
import requests

import azure.functions as func
from azure.functions.decorators import FunctionApp
from azure.data.tables import TableServiceClient
from azure.storage.blob import BlobServiceClient
from azure.core.exceptions import ResourceExistsError

# Configure logging
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "DEBUG"),
    format="%(asctime)s %(levelname)s %(name)s %(message)s"
)

# Constants and configuration
BUNGIE_API_BASE = "https://www.bungie.net/Platform"
API_KEY = os.getenv("BUNGIE_API_KEY")
manifest_cache = {}
REQUEST_TIMEOUT = 10  # seconds
STORAGE_CONNECTION_STRING = os.getenv("AZURE_STORAGE_CONNECTION_STRING")
BLOB_CONTAINER = "vault-data"
TABLE_NAME = "VaultSessions"

app = FunctionApp()

# ----------------------
# Helper Functions
# ----------------------

def retry_request(method, url, **kwargs):
    """
    Retry logic for Bungie API requests with exponential backoff.
    """
    tries = kwargs.pop("tries", 3)
    delay = kwargs.pop("delay", 1)
    for attempt in range(tries):
        try:
            response = method(url, **kwargs)
            if response.ok:
                return response
            logging.warning("Request failed (status %d): %s", response.status_code, url)
        except Exception as e:
            logging.warning("Request error on attempt %d: %s", attempt + 1, e)
        if attempt < tries - 1:
            time.sleep(delay)
            delay *= 2
    logging.error("Max retries exceeded for request: %s", url)
    raise Exception(f"Request failed after {tries} attempts: {url}")


def get_manifest(headers):
    """
    Fetches and caches the Destiny 2 manifest definitions from Bungie API.
    Returns the manifest definitions as a dictionary.
    """
    if "definitions" in manifest_cache:
        return manifest_cache["definitions"]

    index_resp = retry_request(
        requests.get,
        f"{BUNGIE_API_BASE}/Destiny2/Manifest/",
        headers=headers,
        timeout=REQUEST_TIMEOUT
    )
    if not index_resp.ok:
        logging.error("Failed to fetch manifest index: status %d",
                      index_resp.status_code)
        return {}

    index_data = index_resp.json().get("Response", {})
    en_content_path = index_data.get("jsonWorldComponentContentPaths", {}).get(
        "en", {}).get("DestinyInventoryItemDefinition")
    if not en_content_path:
        logging.error("Manifest path not found in manifest index response")
        return {}

    manifest_url = f"https://www.bungie.net{en_content_path}"
    manifest_resp = retry_request(
        requests.get,
        manifest_url,
        timeout=REQUEST_TIMEOUT
    )
    if not manifest_resp.ok:
        logging.error("Failed to fetch manifest content: status %d",
                      manifest_resp.status_code)
        return {}

    definitions = manifest_resp.json()
    manifest_cache["definitions"] = definitions
    return definitions


def save_vault_blob(membership_id, data):
    """
    Saves full vault data to Azure Blob Storage for the given membership_id.
    Overwrites any existing blob with the same name.
    """
    try:
        blob_service = BlobServiceClient.from_connection_string(
            STORAGE_CONNECTION_STRING)
        container = blob_service.get_container_client(BLOB_CONTAINER)
        # Ensure container exists
        try:
            container.create_container()
        except ResourceExistsError:
            pass  # Container may already exist
        blob_name = f"{membership_id}.json"
        container.upload_blob(blob_name, data=json.dumps(data), overwrite=True)
        logging.info("Vault data saved to blob: %s/%s",
                     BLOB_CONTAINER, blob_name)
    except Exception as e:
        logging.error("Failed to save vault data to blob: %s", e)
        raise


def store_session_metadata(membership_id, membership_type, character_summary):
    """
    Stores session metadata in Azure Table Storage for the given membership_id.
    Upserts the entity with membership_type and character IDs.
    """
    try:
        table_service = TableServiceClient.from_connection_string(
            STORAGE_CONNECTION_STRING)
        table_client = table_service.get_table_client(TABLE_NAME)
        # Ensure table exists
        try:
            table_client.create_table()
        except ResourceExistsError:
            pass  # Table may already exist
        entity = {
            "PartitionKey": "VaultSession",
            "RowKey": membership_id,
            "membershipType": membership_type,
            "characterIds": json.dumps(list(character_summary.keys()))
        }
        table_client.upsert_entity(entity=entity)
        logging.info(
            "Session metadata stored in table: %s, RowKey: %s", TABLE_NAME, membership_id)
    except Exception as e:
        logging.error("Failed to store session metadata: %s", e)
        raise


def compute_hash(content):
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def save_dim_backup_blob(membership_id, dim_json_str):
    try:
        blob_service = BlobServiceClient.from_connection_string(STORAGE_CONNECTION_STRING)
        container = blob_service.get_container_client("dim-backups")
        try:
            container.create_container()
        except ResourceExistsError:
            pass
        timestamp = datetime.datetime.utcnow().isoformat()
        blob_name = f"dim-backup-{membership_id}-{timestamp}.json"
        container.upload_blob(blob_name, dim_json_str, overwrite=True)

        hash_key = compute_hash(dim_json_str)
        table_service = TableServiceClient.from_connection_string(STORAGE_CONNECTION_STRING)
        table_client = table_service.get_table_client(TABLE_NAME)
        try:
            table_client.create_table()
        except ResourceExistsError:
            pass
        metadata = {
            "PartitionKey": "DimBackup",
            "RowKey": hash_key,
            "membershipId": membership_id,
            "timestamp": timestamp
        }
        table_client.upsert_entity(metadata)
        logging.info("DIM backup saved and metadata stored.")
    except Exception as e:
        logging.error("Failed to save DIM backup: %s", e)
        raise

# ----------------------
# Route Handler Functions
# ----------------------

@app.route(route="assistant/init", methods=["POST"], auth_level=func.AuthLevel.ANONYMOUS)
def assistant_init(req: func.HttpRequest) -> func.HttpResponse:
    """
    Initializes the assistant by authenticating the user and fetching their Destiny 2 character summary.
    """
    logging.info("[assistant/init] POST request received.")
    try:
        access_token = req.get_json().get("access_token")
        if not access_token:
            return func.HttpResponse("Missing access_token", status_code=400)
    except ValueError:
        return func.HttpResponse("Invalid JSON body", status_code=400)

    headers = {
        "Authorization": f"Bearer {access_token}",
        "X-API-Key": API_KEY
    }

    # Membership lookup
    profile_url = f"{BUNGIE_API_BASE}/User/GetMembershipsForCurrentUser/"
    profile_resp = retry_request(
        requests.get, profile_url, headers=headers, timeout=REQUEST_TIMEOUT)
    if not profile_resp.ok:
        return func.HttpResponse("Failed to get membership", status_code=profile_resp.status_code)

    profile_data = profile_resp.json()["Response"]
    if not profile_data.get("destinyMemberships"):
        return func.HttpResponse("No Destiny memberships found", status_code=404)
    membership = profile_data["destinyMemberships"][0]
    membership_id = membership["membershipId"]
    membership_type = membership["membershipType"]

    # Confirm manifest is loaded
    _ = get_manifest(headers)

    # Get character list
    characters_url = f"{BUNGIE_API_BASE}/Destiny2/{membership_type}/Profile/{membership_id}/?components=200"
    char_resp = retry_request(
        requests.get, characters_url, headers=headers, timeout=REQUEST_TIMEOUT)
    if not char_resp.ok:
        return func.HttpResponse("Failed to get characters", status_code=char_resp.status_code)

    characters_data = char_resp.json()["Response"]["characters"]["data"]
    character_summary = {
        char_id: {
            "classType": char["classType"],
            "light": char["light"],
            "raceHash": char["raceHash"]
        } for char_id, char in characters_data.items()
    }

    response = {
        "message": "Assistant initialized.",
        "membershipId": membership_id,
        "membershipType": membership_type,
        "characters": character_summary,
        "manifestReady": True
    }
    logging.info("[assistant/init] Responding with assistant initialization data.")
    return func.HttpResponse(json.dumps(response, indent=2), mimetype="application/json")


@app.route(route="", methods=["POST"], auth_level=func.AuthLevel.ANONYMOUS)
def main(req: func.HttpRequest) -> func.HttpResponse:
    """
    Main entry point for the Vault assistant. Accepts either an access_token or a vault_data_path.
    """
    logging.info("[main] POST request received.")
    try:
        body = req.get_json()
    except ValueError:
        return func.HttpResponse("Invalid JSON", status_code=400)

    access_token = body.get("access_token")
    vault_data_path = body.get("vault_data_path")

    if not access_token and not vault_data_path:
        return func.HttpResponse("Missing access_token or vault_data_path", status_code=400)

    response_payload = {}
    if access_token:
        headers = {
            "Authorization": f"Bearer {access_token}",
            "X-API-Key": API_KEY
        }
        profile_url = f"{BUNGIE_API_BASE}/User/GetMembershipsForCurrentUser/"
        profile_resp = retry_request(
            requests.get, profile_url, headers=headers, timeout=REQUEST_TIMEOUT)
        if not profile_resp.ok:
            return func.HttpResponse("Failed to get membership data", status_code=profile_resp.status_code)
        profile_data = profile_resp.json().get("Response", {})
        if not profile_data.get("destinyMemberships"):
            return func.HttpResponse("No Destiny memberships found", status_code=404)
        membership = profile_data["destinyMemberships"][0]
        membership_id = membership.get("membershipId")
        membership_type = membership.get("membershipType")
        display_name = membership.get("displayName", "")
        response_payload = {
            "message": "Vault assistant initialized.",
            "membershipId": membership_id,
            "membershipType": membership_type,
            "userInfo": display_name
        }
    elif vault_data_path:
        response_payload = {
            "message": "Vault assistant initialized with saved data.",
            "vaultDataPath": vault_data_path,
            "stub": "Loading from vault data path not yet implemented."
        }
    logging.info("[main] Responding with payload: %s", response_payload.get("message", "No message"))
    return func.HttpResponse(
        json.dumps(response_payload, indent=2),
        mimetype="application/json"
    )


@app.route(route="auth", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def auth(req: func.HttpRequest) -> func.HttpResponse:
    """
    Handles Bungie OAuth callback and exchanges code for access and refresh tokens.
    """
    logging.info("[auth] GET request received.")
    code = req.params.get("code")
    if not code:
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
    except Exception as e:
        logging.error("Token exchange failed: %s", e)
        return func.HttpResponse("OAuth token exchange failed.", status_code=500)
    # Save token info to Azure Table Storage
    try:
        table_service = TableServiceClient.from_connection_string(
            STORAGE_CONNECTION_STRING)
        table_client = table_service.get_table_client(TABLE_NAME)
        try:
            table_client.create_table()
        except ResourceExistsError:
            pass  # Table may already exist
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
                    membership_id_val = profile_data["destinyMemberships"][0].get("membershipId", "")
        except Exception as e:
            logging.warning("Could not retrieve membershipId for token_entity: %s", e)
        token_entity = {
            "PartitionKey": "AuthSession",
            "RowKey": "last",
            "AccessToken": token_data.get("access_token", ""),
            "RefreshToken": token_data.get("refresh_token", ""),
            "ExpiresIn": str(token_data.get("expires_in", "3600")),
            "membershipId": membership_id_val
        }
        table_client.upsert_entity(entity=token_entity)
        logging.info("Token data stored in table storage for session.")
    except Exception as e:
        logging.error("Failed to store token data: %s", e)
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
    """
    Returns the user's Destiny 2 vault inventory items.
    """
    logging.info("[vault] POST request received.")
    try:
        access_token = req.get_json().get("access_token")
    except ValueError:
        return func.HttpResponse("Invalid JSON body", status_code=400)

    if not access_token:
        try:
            table_service = TableServiceClient.from_connection_string(
                STORAGE_CONNECTION_STRING)
            table_client = table_service.get_table_client(TABLE_NAME)
            entity = table_client.get_entity(
                partition_key="AuthSession", row_key="last")
            access_token = entity.get("AccessToken")
            if not access_token:
                return func.HttpResponse("No cached access_token available. Please authenticate.", status_code=403)
        except Exception as e:
            logging.error("Token retrieval from table failed: %s", e)
            return func.HttpResponse("No cached access_token available. Please authenticate.", status_code=403)
    headers = {
        "Authorization": f"Bearer {access_token}",
        "X-API-Key": API_KEY
    }
    profile_url = f"{BUNGIE_API_BASE}/User/GetMembershipsForCurrentUser/"
    profile_resp = retry_request(
        requests.get, profile_url, headers=headers, timeout=REQUEST_TIMEOUT)
    if not profile_resp.ok:
        return func.HttpResponse("Failed to get membership", status_code=profile_resp.status_code)
    profile_data = profile_resp.json()["Response"]
    membership = profile_data["destinyMemberships"][0]
    membership_id = membership["membershipId"]
    membership_type = membership["membershipType"]
    inventory_url = f"{BUNGIE_API_BASE}/Destiny2/{membership_type}/Profile/{membership_id}/?components=102"
    inv_resp = retry_request(
        requests.get, inventory_url, headers=headers, timeout=REQUEST_TIMEOUT)
    if not inv_resp.ok:
        return func.HttpResponse("Failed to get vault inventory", status_code=inv_resp.status_code)
    inventory = inv_resp.json(
    )["Response"]["profileInventory"]["data"]["items"]
    save_vault_blob(membership_id, inventory)
    logging.info("[vault] Responding with vault inventory data.")
    return func.HttpResponse(json.dumps(inventory, indent=2), mimetype="application/json")


@app.route(route="characters", methods=["POST"], auth_level=func.AuthLevel.ANONYMOUS)
def characters(req: func.HttpRequest) -> func.HttpResponse:
    """
    Returns the user's Destiny 2 character equipment data.
    """
    logging.info("[characters] POST request received.")
    try:
        access_token = req.get_json().get("access_token")
    except ValueError:
        return func.HttpResponse("Invalid JSON body", status_code=400)

    if not access_token:
        try:
            table_service = TableServiceClient.from_connection_string(
                STORAGE_CONNECTION_STRING)
            table_client = table_service.get_table_client(TABLE_NAME)
            entity = table_client.get_entity(
                partition_key="AuthSession", row_key="last")
            access_token = entity.get("AccessToken")
            if not access_token:
                return func.HttpResponse("No cached access_token available. Please authenticate.", status_code=403)
        except Exception as e:
            logging.error("Token retrieval from table failed: %s", e)
            return func.HttpResponse("No cached access_token available. Please authenticate.", status_code=403)
    headers = {
        "Authorization": f"Bearer {access_token}",
        "X-API-Key": API_KEY
    }
    profile_url = f"{BUNGIE_API_BASE}/User/GetMembershipsForCurrentUser/"
    profile_resp = retry_request(
        requests.get, profile_url, headers=headers, timeout=REQUEST_TIMEOUT)
    if not profile_resp.ok:
        return func.HttpResponse("Failed to get membership", status_code=profile_resp.status_code)
    profile_data = profile_resp.json()["Response"]
    membership = profile_data["destinyMemberships"][0]
    membership_id = membership["membershipId"]
    membership_type = membership["membershipType"]
    char_url = f"{BUNGIE_API_BASE}/Destiny2/{membership_type}/Profile/{membership_id}/?components=205"
    char_resp = retry_request(
        requests.get, char_url, headers=headers, timeout=REQUEST_TIMEOUT)
    if not char_resp.ok:
        return func.HttpResponse("Failed to get character equipment", status_code=char_resp.status_code)
    equipment = char_resp.json()["Response"]["characterEquipment"]["data"]
    save_vault_blob(membership_id + "-characters", equipment)
    logging.info("[characters] Responding with character equipment data.")
    return func.HttpResponse(json.dumps(equipment, indent=2), mimetype="application/json")


@app.route(route="manifest/item", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def manifest_item(req: func.HttpRequest) -> func.HttpResponse:
    """
    Returns the manifest definition for a given item hash.
    """
    logging.info("[manifest/item] GET request received.")
    item_hash = req.params.get("id")
    if not item_hash:
        return func.HttpResponse("Missing item hash", status_code=400)
    headers = {
        "X-API-Key": API_KEY
    }
    definitions = get_manifest(headers)
    definition = definitions.get(item_hash)
    if not definition:
        return func.HttpResponse("Item not found in manifest", status_code=404)
    logging.info("[manifest/item] Responding with manifest item data.")
    return func.HttpResponse(json.dumps(definition, indent=2), mimetype="application/json")


@app.route(route="token", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def token(req: func.HttpRequest) -> func.HttpResponse:
    """
    Returns a valid access token from table storage, refreshing it with the refresh token if needed.
    """
    logging.info("[token] GET request received.")
    try:
        table_service = TableServiceClient.from_connection_string(
            STORAGE_CONNECTION_STRING)
        table_client = table_service.get_table_client(TABLE_NAME)
        try:
            entity = table_client.get_entity(
                partition_key="AuthSession", row_key="last")
            access_token = entity.get("AccessToken")
            if not access_token:
                return func.HttpResponse("No valid session found. Please re-authenticate via /auth.", status_code=403)
            logging.info("[token] Responding with access token.")
            return func.HttpResponse(json.dumps({"access_token": access_token}), mimetype="application/json")
        except Exception:
            return func.HttpResponse("No valid session found. Please re-authenticate via /auth.", status_code=403)
    except Exception as e:
        logging.error("Token fetch failed: %s", e)
        return func.HttpResponse("Failed to fetch token.", status_code=500)


@app.route(route="dim/backup", methods=["POST"], auth_level=func.AuthLevel.ANONYMOUS)
def dim_backup(req: func.HttpRequest) -> func.HttpResponse:
    """
    Uploads a DIM backup and stores it in blob storage with metadata.
    """
    logging.info("[dim/backup] POST request received.")
    try:
        body = req.get_json()
        membership_id = body.get("membership_id")
        dim_backup = body.get("dim_backup")
        if not membership_id or not dim_backup:
            return func.HttpResponse("Missing membership_id or dim_backup", status_code=400)
        save_dim_backup_blob(membership_id, dim_backup)
        return func.HttpResponse("DIM backup saved successfully.", status_code=200)
    except Exception as e:
        logging.error("[dim/backup] Error: %s", e)
        return func.HttpResponse("Failed to save DIM backup", status_code=500)


@app.route(route="dim/list", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def dim_list(req: func.HttpRequest) -> func.HttpResponse:
    """
    Lists available DIM backups stored in blob storage for the current membership ID.
    """
    logging.info("[dim/list] GET request received.")
    try:
        table_service = TableServiceClient.from_connection_string(STORAGE_CONNECTION_STRING)
        table_client = table_service.get_table_client(TABLE_NAME)
        entity = table_client.get_entity(partition_key="AuthSession", row_key="last")
        membership_id = entity.get("membershipId")
        if not membership_id:
            return func.HttpResponse("No stored membership ID found.", status_code=400)
        blob_service = BlobServiceClient.from_connection_string(STORAGE_CONNECTION_STRING)
        container = blob_service.get_container_client("dim-backups")
        blobs = container.list_blobs(name_starts_with=f"dim-backup-{membership_id}-")
        blob_names = [blob.name for blob in blobs]
        return func.HttpResponse(json.dumps({"backups": blob_names}, indent=2), mimetype="application/json")
    except Exception as e:
        logging.error("[dim/list] Error: %s", e)
        return func.HttpResponse("Failed to list DIM backups", status_code=500)


@app.route(route="token/refresh", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def refresh_token(req: func.HttpRequest) -> func.HttpResponse:
    """
    Refreshes access token using the stored refresh token and updates table storage.
    """
    logging.info("[token/refresh] GET request received.")
    try:
        table_service = TableServiceClient.from_connection_string(STORAGE_CONNECTION_STRING)
        table_client = table_service.get_table_client(TABLE_NAME)
        entity = table_client.get_entity(partition_key="AuthSession", row_key="last")
        refresh_token_val = entity.get("RefreshToken")
        if not refresh_token_val:
            return func.HttpResponse("No refresh token found. Please re-authenticate.", status_code=403)
        token_url = "https://www.bungie.net/platform/app/oauth/token/"
        payload = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token_val,
            "client_id": os.environ.get("BUNGIE_CLIENT_ID"),
            "client_secret": os.environ.get("BUNGIE_CLIENT_SECRET"),
        }
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        response = retry_request(requests.post, token_url, data=payload, headers=headers, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        token_data = response.json()
        entity.update({
            "AccessToken": token_data.get("access_token", ""),
            "RefreshToken": token_data.get("refresh_token", ""),
            "ExpiresIn": str(token_data.get("expires_in", "3600"))
        })
        table_client.upsert_entity(entity=entity)
        return func.HttpResponse(json.dumps({"access_token": token_data["access_token"]}), mimetype="application/json")
    except Exception as e:
        logging.error("Token refresh failed: %s", e)
        return func.HttpResponse("Failed to refresh token.", status_code=500)
