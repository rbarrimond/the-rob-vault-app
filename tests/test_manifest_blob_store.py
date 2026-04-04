"""Unit tests for the manifest blob store."""

# pylint: disable=import-error

from VaultSentinelPlatform.manifest.blob_store import ManifestBlobStore


def test_blob_store_uses_versioned_manifest_names():
    """Manifest blobs should be versioned so the native SQLite payload can be cached safely."""
    store = ManifestBlobStore(storage_connection_string="UseDevelopmentStorage=true")
    assert (
        store.blob_name_for_version("2026.04.03.1200-1")
        == "manifest/2026.04.03.1200-1/world.content"
    )


def test_blob_store_round_trips_sqlite_bytes(tmp_path):
    """The blob store should persist and hydrate the raw SQLite bytes unchanged."""
    payload = b"SQLite format 3\x00manifest-bytes"
    saved = {}

    def _fake_save(connection_string, container_name, blob_name, data, content_type=None):
        saved["args"] = (connection_string, container_name, blob_name, data, content_type)

    def _fake_load(connection_string, container_name, blob_name):
        assert (connection_string, container_name, blob_name) == saved["args"][:3]
        return payload

    store = ManifestBlobStore(
        storage_connection_string="UseDevelopmentStorage=true",
        save_blob_func=_fake_save,
        load_blob_func=_fake_load,
    )

    store.save_manifest_bytes("2026.04.03.1200-1", payload)

    hydrated_path = tmp_path / "manifest.content"
    assert store.hydrate_manifest_to_path("2026.04.03.1200-1", str(hydrated_path)) is True
    assert hydrated_path.read_bytes() == payload
