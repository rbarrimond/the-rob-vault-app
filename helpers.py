# helpers.py
#
"""
Utility functions for Destiny 2 manifest management, Azure Blob/Table Storage operations, and related helpers.

This module provides:
    - Manifest hash normalization and lookup
    - API request retry logic
    - SHA256 hashing
    - Azure Blob and Table Storage save/load helpers
    - Destiny 2 manifest download, extraction, and caching
    - DIM backup save and metadata management
"""
import time
import logging
import hashlib
import datetime
import os
import tempfile
import json
import sqlite3
import zlib
import zipfile

import requests

from azure.storage.blob import BlobServiceClient
from azure.data.tables import TableServiceClient
from azure.core.exceptions import ResourceExistsError

def normalize_item_hash(item_hash):
    """
    Convert a Destiny 2 item hash to an unsigned 32-bit integer string for manifest lookup.

    Args:
        item_hash (int or str): The item hash to normalize.

    Returns:
        str: Unsigned 32-bit integer string representation of the item hash.
    """
    try:
        # Accept int or str
        h = int(item_hash)
        h &= 0xFFFFFFFF
        return str(h)
    except Exception:
        return str(item_hash)

def retry_request(method, url, **kwargs):
    """
    Perform an API request with exponential backoff retry logic.

    Args:
        method (callable): The requests method (e.g., requests.get).
        url (str): The URL to request.
        **kwargs: Additional arguments for the request, plus 'tries' and 'delay'.

    Returns:
        requests.Response: The response object if successful.

    Raises:
        RuntimeError: If all retry attempts fail.
    """
    tries = kwargs.pop("tries", 3)
    delay = kwargs.pop("delay", 1)
    for attempt in range(tries):
        try:
            response = method(url, **kwargs)
            if response.ok:
                return response
            logging.warning("Request failed (status %d): %s",
                            response.status_code, url)
        except requests.RequestException as exc:
            logging.warning("Request error on attempt %d: %s",
                            attempt + 1, exc)
        if attempt < tries - 1:
            logging.info(
                "Retrying request in %d seconds (attempt %d/%d)", delay, attempt + 2, tries)
            time.sleep(delay)
            delay *= 2
    logging.error("Max retries exceeded for request: %s", url)
    raise RuntimeError(f"Request failed after {tries} attempts: {url}")

def compute_hash(content):
    """
    Compute the SHA256 hash of a string.

    Args:
        content (str): The string to hash.

    Returns:
        str: SHA256 hash of the input string.
    """
    return hashlib.sha256(content.encode("utf-8")).hexdigest()

def save_blob(connection_string, container_name, blob_name, data):
    """
    Save data to Azure Blob Storage in the specified container and blob name.

    Args:
        connection_string (str): Azure Blob Storage connection string.
        container_name (str): Name of the blob container.
        blob_name (str): Name of the blob to create or overwrite.
        data (bytes or str): Data to upload.
    """
    blob_service = BlobServiceClient.from_connection_string(connection_string)
    container = blob_service.get_container_client(container_name)
    try:
        container.create_container()
    except ResourceExistsError:
        logging.info("Blob container '%s' already exists.", container_name)
    container.upload_blob(blob_name, data, overwrite=True)
    logging.info("Saved blob: %s/%s", container_name, blob_name)

def load_blob(connection_string, container_name, blob_name):
    """
    Load data from Azure Blob Storage in the specified container and blob name.

    Args:
        connection_string (str): Azure Blob Storage connection string.
        container_name (str): Name of the blob container.
        blob_name (str): Name of the blob to download.

    Returns:
        bytes or None: Blob data if found, otherwise None.
    """
    blob_service = BlobServiceClient.from_connection_string(connection_string)
    container = blob_service.get_container_client(container_name)
    try:
        blob_client = container.get_blob_client(blob_name)
        data = blob_client.download_blob().readall()
        logging.info("Loaded blob: %s/%s", container_name, blob_name)
        return data
    except Exception as e:
        logging.error("Failed to load blob %s/%s: %s",
                      container_name, blob_name, e)
        return None

def save_table_entity(connection_string, table_name, entity):
    """
    Save or upsert an entity to Azure Table Storage.

    Args:
        connection_string (str): Azure Table Storage connection string.
        table_name (str): Name of the table.
        entity (dict): Entity to save or upsert.
    """
    table_service = TableServiceClient.from_connection_string(
        connection_string)
    table_client = table_service.get_table_client(table_name)
    try:
        table_client.create_table()
    except ResourceExistsError:
        logging.info("Table '%s' already exists.", table_name)
    table_client.upsert_entity(entity=entity)
    logging.info("Saved entity to table: %s, RowKey: %s",
                 table_name, entity.get("RowKey"))

def get_manifest(headers, manifest_cache, api_base, retry_request_func, timeout, required_types=None):
    """
    Fetch and cache Destiny 2 manifest definitions from the Bungie API.

    Retrieves the manifest index, checks if the cached manifest is up-to-date, and returns cached
    definitions if available. If not, downloads the manifest database, extracts required tables,
    and parses their contents (handling decompression and JSON parsing as needed). Results are
    stored in manifest_cache for future use.

    Args:
        headers (dict): HTTP headers for Bungie API requests.
        manifest_cache (dict): Cache object to store manifest definitions and version.
        api_base (str): Base URL for Bungie API.
        retry_request_func (callable): Function to perform requests with retry logic.
        timeout (int): Timeout for API requests in seconds.
        required_types (list, optional): List of manifest definition table names to extract. If None,
            all available tables are loaded.

    Returns:
        dict: {'definitions': loaded manifest tables, 'version': manifest version}. Empty dict on error.
    """

    # Get manifest version and download index
    index_resp = retry_request_func(
        requests.get,
        f"{api_base}/Destiny2/Manifest/",
        headers=headers,
        timeout=timeout
    )
    if not index_resp.ok:
        logging.error("Manifest index fetch failed with status code %d.",  index_resp.status_code)
        return {}
    index_data = index_resp.json().get("Response", {})
    manifest_version = index_data.get("version")
    if (manifest_cache.get("version") == manifest_version and manifest_cache.get("definitions")):
        logging.info("Manifest definitions loaded from cache (version: %s) %s", manifest_version, manifest_cache["definitions"])
        return {
            "definitions": manifest_cache["definitions"],
            "version": manifest_version
        }

    # Download entire manifest
    sqlite_path = index_data.get("mobileWorldContentPaths", {}).get("en")
    if not sqlite_path:
        logging.error("Manifest index response missing SQLite path.")
        return {}
    url = f"https://www.bungie.net{sqlite_path}"
    resp = retry_request_func(requests.get, url, timeout=timeout)
    if not resp.ok:
        logging.error("Manifest ZIP download failed with status code %d.", resp.status_code)
        return {}
    with tempfile.NamedTemporaryFile(delete=False, mode="wb") as tmp_file:
        tmp_file.write(resp.content)
        zip_path = tmp_file.name

    manifest = {}
    extracted_sqlite_path = None

    try:
        # Extract SQLite file from ZIP and save to temporary location
        with zipfile.ZipFile(zip_path, 'r') as zf:
            # Find the largest .content file (the manifest DB)
            manifest_files = [info for info in zf.infolist(
            ) if info.filename.endswith('.content')]
            if not manifest_files:
                logging.error("No .content file found in manifest ZIP archive.")
                return {}
            manifest_info = max(
                manifest_files, key=lambda info: info.file_size)
            with tempfile.NamedTemporaryFile(delete=False, mode="wb") as sqlite_file:
                with zf.open(manifest_info.filename, 'r') as src:
                    sqlite_file.write(src.read())
                extracted_sqlite_path = sqlite_file.name

        # Load required tables from extracted SQLite
        try:
            conn2 = sqlite3.connect(extracted_sqlite_path)
            cursor2 = conn2.cursor()
            available_tables = [r[0] for r in cursor2.execute(
                "SELECT name FROM sqlite_master WHERE type='table';").fetchall()]
            logging.info("Extracted manifest DB tables: %s", available_tables)
            def_types = required_types if required_types else available_tables
            for def_type in def_types:
                if def_type not in available_tables:
                    logging.warning(
                        "Requested definition type '%s' not found in manifest DB tables.", def_type)
                    continue
                try:
                    cursor2.execute(f"SELECT json FROM {def_type}")
                    rows = cursor2.fetchall()
                    defs = {}
                    for row in rows:
                        try:
                            # Try decompressing, fallback to plain JSON if decompress fails
                            data = row[0]
                            if isinstance(data, str):
                                # Try to parse as JSON first
                                try:
                                    obj = json.loads(data)
                                    hash_val = str(obj.get("hash", obj.get(
                                        "itemHash", obj.get("id", None))))
                                    if hash_val:
                                        defs[hash_val] = obj
                                    continue
                                except Exception:
                                    data = data.encode('utf-8')
                            try:
                                decompressed = zlib.decompress(data)
                                obj = json.loads(decompressed.decode('utf-8'))
                            except Exception as decomp_err:
                                # If decompression fails, try plain JSON
                                try:
                                    obj = json.loads(data.decode('utf-8') if isinstance(data, bytes) else data)
                                except Exception as json_err:
                                    logging.error("Decompression and plain JSON parse failed for row in table '%s': %s | %s",
                                                   def_type, decomp_err, json_err)
                                    continue
                            hash_val = str(obj.get("hash", obj.get(
                                "itemHash", obj.get("id", None))))
                            if hash_val:
                                defs[hash_val] = obj
                        except Exception as e:
                            logging.error(
                                "Decompression or JSON parse failed for row in table '%s': %s", def_type, e)
                            continue
                    manifest[def_type] = defs
                except Exception as e:
                    logging.error(
                        "Table query or parse failed for '%s': %s", def_type, e)
                    continue
            conn2.close()
        except Exception as e:
            logging.error("Manifest DB inspection or parsing error: %s", e)
            if extracted_sqlite_path:
                os.remove(extracted_sqlite_path)
            return {}
    finally:
        os.remove(zip_path)
        if extracted_sqlite_path:
            os.remove(extracted_sqlite_path)

    manifest_cache["definitions"] = manifest
    manifest_cache["version"] = manifest_version
    return {"definitions": manifest, "version": manifest_version}

def resolve_manifest_hash(item_hash, manifest_cache, definition_types=None):
    """
    Attempt to resolve a hash against multiple manifest definition types.

    Args:
        item_hash (str or int): The item hash to resolve.
        manifest_cache (dict): Manifest cache containing definitions.
        definition_types (list, optional): List of definition types to search. If None, all loaded
            types are used.

    Returns:
        tuple: (definition object, definition type) if found, otherwise (None, None).
    """
    # Use all loaded definition types if not provided
    if not definition_types:
        definition_types = list(manifest_cache.keys())
    item_hash = str(item_hash)
    for def_type in definition_types:
        defs = manifest_cache.get(def_type, {})
        if defs and item_hash in defs:
            return defs[item_hash], def_type
    return None, None

def save_dim_backup_blob(connection_string, table_name, membership_id, dim_json_str, timestamp=None):
    """
    Save a DIM backup to blob storage and store its metadata in table storage.

    Args:
        connection_string (str): Azure Storage connection string.
        table_name (str): Name of the metadata table.
        membership_id (str): Destiny membership ID.
        dim_json_str (str): DIM backup data as a JSON string.
        timestamp (str, optional): Timestamp for the backup. If None, current UTC time is used.

    Returns:
        tuple: (blob_name, hash_key, timestamp) of the saved backup.
    """
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
    table_service = TableServiceClient.from_connection_string(
        connection_string)
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
