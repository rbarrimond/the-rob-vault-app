"""
Data models for Bungie Destiny vault and character inventory management.
Includes Pydantic models for Item, Character, and Vault entities.
"""
from typing import Dict, List, Optional

from pydantic import BaseModel


class Item(BaseModel):
    """
    Represents an item in Bungie's Destiny vault or character inventory.
    Includes metadata, stats, and ownership information.
    """
    itemHash: str
    itemInstanceId: Optional[str]
    itemName: str
    itemType: str
    itemTier: Optional[str]
    stats: Dict[str, int] = {}
    location: Optional[str]
    isEquipped: bool = False
    owner: Optional[str]

class Character(BaseModel):
    """
    Represents a Destiny character (Hunter, Titan, Warlock).
    Contains character-specific items and class type.
    """
    charId: str
    name: str
    classType: str
    items: List[Item] = []

class Vault(BaseModel):
    """
    Represents the shared Destiny vault.
    Contains items accessible to all characters.
    """
    items: List[Item] = []
