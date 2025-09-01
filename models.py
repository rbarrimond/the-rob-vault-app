"""
Data models for Bungie Destiny vault and character inventory management.
Includes Pydantic models for Item, Character, and Vault entities.
"""
from typing import Dict, List, Optional
from datetime import datetime

from pydantic import BaseModel


class Item(BaseModel):
    """
    Represents an item in Bungie's Destiny vault or character inventory.
    Includes metadata, stats, and ownership information.
    """
    itemHash: str  # Destiny 2 item hash (unique identifier)
    itemInstanceId: Optional[str]  # Instance ID for the item (if applicable)
    itemName: str  # Display name of the item
    itemType: str  # Type of item (e.g., weapon, armor)
    itemTier: Optional[str]  # Tier of item (e.g., Legendary, Exotic)
    stats: Dict[str, int] = {}  # Stat values for the item
    location: Optional[str]  # Where the item is stored (vault, character)
    isEquipped: bool = False  # Whether the item is currently equipped
    owner: Optional[str]  # Owner of the item (character ID or vault)

class Character(BaseModel):
    """
    Represents a Destiny character (Hunter, Titan, Warlock).
    Contains character-specific items and class type.
    """
    charId: str  # Destiny 2 character ID
    name: str  # Character name
    classType: str  # Class type (Hunter, Titan, Warlock)
    items: List[Item] = []  # List of items for this character
    data_version: Optional[datetime] = None  # Bungie dateLastPlayed as datetime for freshness/version

class Vault(BaseModel):
    """
    Represents the shared Destiny vault.
    Contains items accessible to all characters.
    """
    items: List[Item] = []  # List of items in the shared vault
    data_version: Optional[datetime] = None  # Bungie dateLastPlayed as datetime for freshness/version
