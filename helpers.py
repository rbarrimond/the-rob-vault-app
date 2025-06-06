import time
import logging
import hashlib
import datetime
import requests

from azure.storage.blob import BlobServiceClient
from azure.data.tables import TableServiceClient
from azure.core.exceptions import ResourceExistsError

# Retry logic for API requests with exponential backoff
def retry_request(method, url, **kwargs):
    """Retry logic for API requests with exponential backoff."""
    tries = kwargs.pop("tries", 3)
    delay = kwargs.pop("delay", 1)
    for attempt in range(tries):
        try:
            response = method(url, **kwargs)
            if response.ok:
                return response
            logging.warning("Request failed (status %d): %s", response.status_code, url)
        except requests.RequestException as exc:
            logging.warning("Request error on attempt %d: %s", attempt + 1, exc)
        if attempt < tries - 1:
            logging.info("Retrying request in %d seconds (attempt %d/%d)", delay, attempt + 2, tries)
            time.sleep(delay)
            delay *= 2
    logging.error("Max retries exceeded for request: %s", url)
    raise RuntimeError(f"Request failed after {tries} attempts: {url}")

# Compute SHA256 hash
def compute_hash(content):
    """Compute SHA256 hash of the given content string."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()

# Save data to Azure Blob Storage
def save_blob(connection_string, container_name, blob_name, data):
    """Save data to Azure Blob Storage in the specified container and blob name."""
    blob_service = BlobServiceClient.from_connection_string(connection_string)
    container = blob_service.get_container_client(container_name)
    try:
        container.create_container()
    except ResourceExistsError:
        logging.info("Blob container '%s' already exists.", container_name)
    container.upload_blob(blob_name, data, overwrite=True)
    logging.info("Saved blob: %s/%s", container_name, blob_name)

# Save entity to Azure Table Storage
def save_table_entity(connection_string, table_name, entity):
    """Save or upsert an entity to Azure Table Storage."""
    table_service = TableServiceClient.from_connection_string(connection_string)
    table_client = table_service.get_table_client(table_name)
    try:
        table_client.create_table()
    except ResourceExistsError:
        logging.info("Table '%s' already exists.", table_name)
    table_client.upsert_entity(entity=entity)
    logging.info("Saved entity to table: %s, RowKey: %s", table_name, entity.get("RowKey"))

# Fetch and cache Destiny 2 manifest definitions
def get_manifest(headers, manifest_cache, api_base, retry_request_func, timeout):
    """Fetch and cache Destiny 2 manifest definitions from the Bungie API."""
    if "definitions" in manifest_cache:
        logging.info("Manifest definitions found in cache.")
        return manifest_cache["definitions"]
    index_resp = retry_request_func(
        requests.get,
        f"{api_base}/Destiny2/Manifest/",
        headers=headers,
        timeout=timeout
    )
    if not index_resp.ok:
        logging.error("Failed to fetch manifest index: status %d", index_resp.status_code)
        return {}
    index_data = index_resp.json().get("Response", {})
    en_content_path = index_data.get("jsonWorldComponentContentPaths", {}).get("en", {}).get("DestinyInventoryItemDefinition")
    if not en_content_path:
        logging.error("Manifest path not found in manifest index response")
        return {}
    manifest_url = f"https://www.bungie.net{en_content_path}"
    manifest_resp = retry_request_func(
        requests.get,
        manifest_url,
        timeout=timeout
    )
    if not manifest_resp.ok:
        logging.error("Failed to fetch manifest content: status %d", manifest_resp.status_code)
        return {}
    definitions = manifest_resp.json()
    manifest_cache["definitions"] = definitions
    logging.info("Manifest definitions loaded and cached.")
    return definitions

# Save DIM backup and metadata
def save_dim_backup_blob(connection_string, table_name, membership_id, dim_json_str, timestamp=None):
    """Save a DIM backup to blob storage and store its metadata in table storage."""
    blob_service = BlobServiceClient.from_connection_string(connection_string)
    container = blob_service.get_container_client("dim-backups")
    try:
        container.create_container()
    except ResourceExistsError:
        logging.info("Blob container 'dim-backups' already exists.")
    if not timestamp:
        timestamp = datetime.datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    blob_name = f"dim-backup-{membership_id}-{timestamp}.json"
    container.upload_blob(blob_name, dim_json_str, overwrite=True)
    logging.info("DIM backup saved to blob: %s", blob_name)
    hash_key = compute_hash(dim_json_str)
    table_service = TableServiceClient.from_connection_string(connection_string)
    table_client = table_service.get_table_client(table_name)
    try:
        table_client.create_table()
    except ResourceExistsError:
        logging.info("Table '%s' already exists.", table_name)
    metadata = {
        "PartitionKey": "DimBackup",
        "RowKey": hash_key,
        "membershipId": membership_id,
        "timestamp": timestamp
    }
    table_client.upsert_entity(metadata)
    logging.info("DIM backup metadata stored in table.")
    return blob_name, hash_key, timestamp
