"""
Module containing constants for Destiny 2 Vault Assistant.
"""

# Bungie manifest definition keys required for decoding and optimizing character loadouts
BUNGIE_REQUIRED_DEFS = [
    # --- Item and Inventory ---
    "DestinyInventoryItemDefinition",      # weapons, armor, ghosts, artifacts, mods, etc.
    "DestinyInventoryBucketDefinition",    # vault, character slots, etc.
    "DestinyItemCategoryDefinition",       # weapon, armor, ghost, etc.
    "DestinyItemTierTypeDefinition",       # Exotic, Legendary, etc.

    # --- Stats and Sockets ---
    "DestinyStatGroupDefinition",          # stat groupings for items
    "DestinyPlugSetDefinition",            # reusable mods/perks
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
