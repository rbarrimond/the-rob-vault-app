# pylint: disable=broad-except, line-too-long
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
import ctypes

import requests

from azure.storage.blob import BlobServiceClient
from azure.data.tables import TableServiceClient
from azure.core.exceptions import ResourceExistsError

def normalize_item_hash(item_hash: int | str) -> str:
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
        h = ctypes.c_uint32(h).value
        return str(h)
    except Exception:
        return str(item_hash)

def retry_request(method: callable, url: str, **kwargs) -> requests.Response:
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

def compute_hash(content: str) -> str:
    """
    Compute the SHA256 hash of a string.

    Args:
        content (str): The string to hash.

    Returns:
        str: SHA256 hash of the input string.
    """
    return hashlib.sha256(content.encode("utf-8")).hexdigest()

def save_blob(connection_string: str, container_name: str, blob_name: str, data: bytes | str, content_type: str = None) -> None:
    """
    Save data to Azure Blob Storage in the specified container and blob name.

    Args:
        connection_string (str): Azure Blob Storage connection string.
        container_name (str): Name of the blob container.
        blob_name (str): Name of the blob to create or overwrite.
        data (bytes or str): Data to upload.
        content_type (str, optional): Content type for the blob.
    """
    blob_service = BlobServiceClient.from_connection_string(connection_string)
    container = blob_service.get_container_client(container_name)
    try:
        container.create_container()
    except ResourceExistsError:
        logging.info("Blob container '%s' already exists.", container_name)
    upload_args = {"overwrite": True}
    if content_type:
        upload_args["content_type"] = content_type
    container.upload_blob(blob_name, data, **upload_args)
    logging.info("Saved blob: %s/%s", container_name, blob_name)

def load_blob(connection_string: str, container_name: str, blob_name: str) -> bytes | None:
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

def save_table_entity(connection_string: str, table_name: str, entity: dict) -> None:
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



def save_dim_backup_blob(connection_string: str, table_name: str, membership_id: str, dim_json_str: str, timestamp: str | None = None) -> tuple[str, str, str]:
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
