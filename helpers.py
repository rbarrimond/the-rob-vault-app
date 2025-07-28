import time
import logging
import hashlib
import datetime
import requests

from azure.storage.blob import BlobServiceClient
from azure.data.tables import TableServiceClient

from azure.core.exceptions import ResourceExistsError

# Normalize Destiny 2 item hash to unsigned 32-bit string
def normalize_item_hash(item_hash):
    """Convert item_hash to unsigned 32-bit int and string for manifest lookup."""
    try:
        # Accept int or str
        h = int(item_hash)
        h &= 0xFFFFFFFF
        return str(h)
    except Exception:
        return str(item_hash)

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
    defs = manifest_cache.get("definitions")
    if defs:
        logging.info("Manifest definitions found in cache.")
        return defs

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
    en_paths = index_data.get("jsonWorldComponentContentPaths", {}).get("en", {})
    def_types = [
        "DestinyInventoryItemDefinition",
        "DestinyPlugItemDefinition",
        "DestinyStatDefinition",
        "DestinySocketTypeDefinition",
        "DestinySocketCategoryDefinition"
    ]
    manifest = {}

    for def_type in def_types:
        path = en_paths.get(def_type)
        if not path:
            logging.error("Manifest index missing path for %s", def_type)
            continue
        url = f"https://www.bungie.net{path}"
        resp = retry_request_func(requests.get, url, timeout=timeout)
        if not resp.ok:
            logging.warning("Failed to fetch %s: status %d", def_type, resp.status_code)
            continue
        resp_json = resp.json()
        manifest[def_type] = resp_json.get("Response", resp_json)
        logging.info("Loaded manifest for %s (entries: %d)", def_type, len(manifest[def_type]))

    found_types = list(manifest)
    missing_types = [t for t in def_types if t not in found_types]
    logging.info("Manifest definition types loaded: %s", found_types)
    if missing_types:
        logging.warning("Manifest definition types missing: %s", missing_types)

    manifest_cache["definitions"] = manifest
    logging.info("All manifest definitions loaded and cached.")
    return manifest


# Attempt to resolve a hash against multiple manifest definition types.
def resolve_manifest_hash(item_hash, manifest_cache, definition_types=None):
    """Attempt to resolve a hash against multiple manifest definition types."""
    if not definition_types:
        definition_types = [
            "DestinyInventoryItemDefinition",
            "DestinyPlugItemDefinition",
            "DestinyStatDefinition",
            "DestinySocketTypeDefinition",
            "DestinySocketCategoryDefinition"
        ]
    item_hash = str(item_hash)
    for def_type in definition_types:
        defs = manifest_cache.get(def_type, {})
        if defs and item_hash in defs:
            return defs[item_hash], def_type
    return None, None

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
