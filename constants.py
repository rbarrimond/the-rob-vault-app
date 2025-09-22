"""
Module containing constants for Destiny 2 Vault Assistant.
"""

import os

# Azure OpenAI and SQL configuration constants
OPENAI_ENDPOINT = os.getenv("AZURE_OPENAI_ENDPOINT")
OPENAI_DEPLOYMENT = os.getenv("AZURE_OPENAI_DEPLOYMENT")
OPENAI_API_VERSION = os.getenv("AZURE_OPENAI_API_VERSION", "2023-05-15")
OPENAI_API_KEY = os.getenv("AZURE_OPENAI_API_KEY")
SQL_SERVER = os.getenv("AZURE_SQL_SERVER")
SQL_DATABASE = os.getenv("AZURE_SQL_DATABASE")
SQL_DRIVER = os.getenv("AZURE_SQL_DRIVER", "ODBC Driver 18 for SQL Server")
SQL_USER = os.getenv("AZURE_SQL_ADMIN_LOGIN")
SQL_PASSWORD = os.getenv("AZURE_SQL_ADMIN_PASSWORD")

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
    # --- Item and Inventory (core lookups for plugs, items, and slots) ---
    "DestinyInventoryItemDefinition",      # weapons, armor, ghosts, artifacts, mods, shaders, ornaments, masterworks
    "DestinyInventoryBucketDefinition",    # vault, character slots, etc.
    "DestinyItemCategoryDefinition",       # weapon/armor/ghost categories
    "DestinyItemTierTypeDefinition",       # Exotic, Legendary, etc.

    # --- Stats and Sockets (instance-readable + display) ---
    "DestinyStatDefinition",               # stat names (Range, Mobility, etc.)
    "DestinyStatGroupDefinition",          # stat groupings for items
    "DestinyPlugSetDefinition",            # reusable/randomized perk pools
    "DestinySocketCategoryDefinition",     # socket categories (e.g., WEAPON PERKS, ARMOR MODS, COSMETICS, MASTERWORK)
    "DestinySocketTypeDefinition",         # socket compatibility / plug whitelist
    "DestinyEnergyTypeDefinition",         # armor energy type names (Any/Arc/Solar/Void/Stasis/Strand)

    # --- Perks / Traits (behavior flags vs. plugs) ---
    "DestinySandboxPerkDefinition",        # 302 sandbox perks (artifact passives, always-on behaviors)
    "DestinyTraitDefinition",              # foundry/slot traits (for labeling & grouping)

    # --- Damage / Breakers ---
    "DestinyDamageTypeDefinition",         # Arc, Solar, Void, Stasis, Strand, Kinetic/None
    "DestinyBreakerTypeDefinition",        # Barrier/Overload/Unstoppable (for artifact anti-champion context)

    # --- Artifacts / Unlocks ---
    "DestinyArtifactDefinition",           # seasonal artifacts & their socket layout
    "DestinyUnlockDefinition",             # equip/feature gates (e.g., cannotEquipReason, artifact unlock flags)

    # --- Subclass and Class Info (for loadout labeling) ---
    "DestinyClassDefinition",              # Titan, Hunter, Warlock
    "DestinyRaceDefinition",               # Human, Awoken, Exo
]

# Maps classType integer values to user-friendly class names
CLASS_TYPE_MAP = {
    0: "Titan",
    1: "Hunter",
    2: "Warlock"
}
