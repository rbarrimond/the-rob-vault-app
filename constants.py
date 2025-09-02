"""
Module containing constants for Destiny 2 Vault Assistant.
"""

import os

# API and Azure configuration constants
BUNGIE_API_BASE = "https://www.bungie.net/Platform"
API_KEY = os.getenv("BUNGIE_API_KEY")
# Default headers for Bungie API requests
DEFAULT_HEADERS = {"X-API-Key": API_KEY}
STORAGE_CONNECTION_STRING = os.getenv("AZURE_STORAGE_CONNECTION_STRING")
BLOB_CONTAINER = "vault-data"
TABLE_NAME = "VaultSessions"
REQUEST_TIMEOUT = 10  # seconds

# Bungie manifest definition keys required for decoding and optimizing character loadouts
BUNGIE_REQUIRED_DEFS = [
    # --- Item and Inventory ---
    "DestinyInventoryItemDefinition",      # weapons, armor, ghosts, artifacts, mods, etc.
    "DestinyInventoryBucketDefinition",    # vault, character slots, etc.
    "DestinyItemCategoryDefinition",       # weapon, armor, ghost, etc.
    "DestinyItemTierTypeDefinition",       # Exotic, Legendary, etc.

    # --- Stats and Sockets ---
    "DestinyStatDefinition",               # item stats (impact, range, etc.)
    "DestinyStatGroupDefinition",          # stat groupings for items
    "DestinyPlugSetDefinition",            # reusable mods/perks
    "DestinySocketCategoryDefinition",     # socket categories (e.g., primary, special)
    "DestinySocketTypeDefinition",         # socket compatibility

    # --- Perks, Intrinsics, Traits ---
    "DestinyTraitDefinition",              # item traits (foundry, slot, etc.)

    # --- Damage Types ---
    "DestinyDamageTypeDefinition",         # Arc, Solar, Void, Stasis, etc.

    # --- Artifacts ---
    "DestinyArtifactDefinition",           # seasonal artifacts

    # --- Subclass and Class Info ---
    "DestinyClassDefinition",              # Titan, Hunter, Warlock
    "DestinyRaceDefinition",               # Human, Awoken, Exo
]

# Maps classType integer values to user-friendly class names
CLASS_TYPE_MAP = {
    0: "Titan",
    1: "Hunter",
    2: "Warlock"
}
