"""
Data models for Bungie Destiny vault and character inventory management.
Includes Pydantic models for Item, Character, and Vault entities.
"""
from datetime import datetime
from typing import Dict, List, Optional

from pydantic import BaseModel
from sqlalchemy import (BigInteger, Boolean, Column, DateTime, ForeignKey,
                        Integer, String)
from sqlalchemy.orm import declarative_base, relationship


class ItemModel(BaseModel):
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

class CharacterModel(BaseModel):
    """
    Represents a Destiny character (Hunter, Titan, Warlock).
    Contains character-specific items and class type.
    """
    charId: str  # Destiny 2 character ID
    name: str  # Character name
    classType: str  # Class type (Hunter, Titan, Warlock)
    items: List[ItemModel] = []  # List of items for this character
    data_version: Optional[datetime] = None  # Bungie dateLastPlayed as datetime for freshness/version

class VaultModel(BaseModel):
    """
    Represents the shared Destiny vault.
    Contains items accessible to all characters.
    """
    items: List[ItemModel] = []  # List of items in the shared vault
    data_version: Optional[datetime] = None  # Bungie dateLastPlayed as datetime for freshness/version

# --- SQLAlchemy ORM Models ---

Base = declarative_base()

class User(Base):
    """
    Represents a Destiny 2 user/account.
    """
    __tablename__ = 'Users'
    user_id = Column(BigInteger, primary_key=True)
    membership_id = Column(String(50), nullable=False)
    membership_type = Column(String(20), nullable=False)
    display_name = Column(String(100))
    created_at = Column(DateTime)
    characters = relationship("Character", back_populates="user")

class Character(Base):
    """
    Represents a Destiny 2 character belonging to a user.
    """
    __tablename__ = 'Characters'
    character_id = Column(BigInteger, primary_key=True)
    user_id = Column(BigInteger, ForeignKey('Users.user_id'), nullable=False)
    class_type = Column(String(50))
    light = Column(Integer)
    race_hash = Column(BigInteger)
    user = relationship("User", back_populates="characters")
    items = relationship("Item", back_populates="character")

class Item(Base):
    """
    Represents an inventory item for a character.
    """
    __tablename__ = 'Items'
    item_id = Column(BigInteger, primary_key=True)
    character_id = Column(BigInteger, ForeignKey('Characters.character_id'))
    item_hash = Column(BigInteger, nullable=False)
    item_instance_id = Column(BigInteger)
    name = Column(String(100))
    type = Column(String(50))
    tier = Column(String(50))
    collectible_hash = Column(BigInteger)
    power_cap_hash = Column(BigInteger)
    season_hash = Column(BigInteger)
    character = relationship("Character", back_populates="items")
    stats = relationship("ItemStat", back_populates="item")
    perks = relationship("ItemPerk", back_populates="item")
    mods = relationship("ItemMod", back_populates="item")
    masterwork = relationship("ItemMasterwork", uselist=False, back_populates="item")
    sockets = relationship("ItemSocket", back_populates="item")

class ItemStat(Base):
    """
    Represents a stat value for an item (e.g., Discipline, Mobility).
    """
    __tablename__ = 'ItemStats'
    item_id = Column(BigInteger, ForeignKey('Items.item_id'), primary_key=True)
    stat_hash = Column(BigInteger, primary_key=True)
    stat_name = Column(String(100))
    stat_value = Column(Integer)
    item = relationship("Item", back_populates="stats")

class ItemPerk(Base):
    """
    Represents a perk available on an item.
    """
    __tablename__ = 'ItemPerks'
    item_id = Column(BigInteger, ForeignKey('Items.item_id'), primary_key=True)
    perk_hash = Column(BigInteger, primary_key=True)
    perk_name = Column(String(100))
    description = Column(String(255))
    icon = Column(String(255))
    item = relationship("Item", back_populates="perks")

class ItemMod(Base):
    """
    Represents a mod available on an item.
    """
    __tablename__ = 'ItemMods'
    item_id = Column(BigInteger, ForeignKey('Items.item_id'), primary_key=True)
    mod_hash = Column(BigInteger, primary_key=True)
    mod_name = Column(String(100))
    description = Column(String(255))
    icon = Column(String(255))
    item = relationship("Item", back_populates="mods")

class ItemMasterwork(Base):
    """
    Represents masterwork details for an item.
    """
    __tablename__ = 'ItemMasterwork'
    item_id = Column(BigInteger, ForeignKey('Items.item_id'), primary_key=True)
    masterwork_hash = Column(BigInteger)
    masterwork_name = Column(String(100))
    description = Column(String(255))
    icon = Column(String(255))
    item = relationship("Item", back_populates="masterwork")

class ItemSocket(Base):
    """
    Represents a socket on an item for customization.
    """
    __tablename__ = 'ItemSockets'
    item_id = Column(BigInteger, ForeignKey('Items.item_id'), primary_key=True)
    socket_index = Column(Integer, primary_key=True)
    socket_type_hash = Column(BigInteger)
    item = relationship("Item", back_populates="sockets")
    plugs = relationship("ItemPlug", back_populates="socket")

class ItemPlug(Base):
    """
    Represents a plug (perk/mod) in a socket, tracks equipped state.
    """
    __tablename__ = 'ItemPlugs'
    item_id = Column(BigInteger, ForeignKey('ItemSockets.item_id'), primary_key=True)
    socket_index = Column(Integer, ForeignKey('ItemSockets.socket_index'), primary_key=True)
    plug_hash = Column(BigInteger, primary_key=True)
    is_equipped = Column(Boolean, default=False)
    socket = relationship("ItemSocket", back_populates="plugs")
