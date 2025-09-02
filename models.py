# pylint: disable=line-too-long
"""
Models for Destiny 2 vault and character inventory management.

This module defines Pydantic models for API serialization and SQLAlchemy ORM models for database persistence.
Includes:
- ItemModel: Pydantic model for Destiny items, with manifest enrichment.
- CharacterModel, VaultModel: Pydantic models for character and vault containers.
- ORM models for SQL database schema.
"""
from datetime import datetime
from typing import Dict, List, Optional

from pydantic import BaseModel
import requests
from sqlalchemy import (BigInteger, Boolean, Column, DateTime, ForeignKey,
                        Integer, String)
from sqlalchemy.orm import declarative_base, relationship

from bungie_session_manager import BungieSessionManager
from helpers import retry_request
from manifest_cache import ManifestCache

# --- Pydantic Models ---
class ItemModel(BaseModel):
    """
    Pydantic model for a Destiny 2 item.

    Attributes:
        itemHash (str): Destiny 2 item hash (unique identifier).
        itemInstanceId (Optional[str]): Instance ID for the item (if applicable).
        itemName (str): Display name of the item.
        itemType (str): Type of item (e.g., weapon, armor).
        itemTier (Optional[str]): Tier of item (e.g., Legendary, Exotic).
        stats (Dict[str, int]): Stat values for the item.
        location (Optional[str]): Where the item is stored (vault, character).
        isEquipped (bool): Whether the item is currently equipped.
        owner (Optional[str]): Owner of the item (character ID or vault).
    """
    itemHash: int
    itemInstanceId: Optional[str]
    itemName: str
    itemType: str
    itemTier: Optional[str]
    stats: Dict[str, int] = {}
    location: Optional[int]
    isEquipped: bool = False
    owner: Optional[str]

    @classmethod
    def from_raw_data(
        cls,
        raw_data: dict,
        session_manager: BungieSessionManager,
        manifest_cache: ManifestCache,
        item_instance_id: str = None
    ) -> "ItemModel":
        """
        Build a fully decoded ItemModel from raw item data and manifest cache.

        Args:
            raw_data (dict): Raw item data from blob or database.
            manifest_cache (ManifestCache): ManifestCache instance for lookups.
            item_instance_id (str, optional): Destiny 2 item instance ID.

        Returns:
            ItemModel: Fully populated item model with manifest enrichment.
        """
        manifest_cache.ensure_manifest()
        norm_hash = raw_data.get("itemHash")
        item_def, _ = manifest_cache.resolve_manifest_hash(norm_hash)
        if not item_def:
            return cls(
                itemHash=norm_hash,
                itemInstanceId=raw_data.get("itemInstanceId"),
                itemName="Unknown",
                itemType="Unknown",
                itemTier=None,
                stats={},
                location=raw_data.get("location"),
                isEquipped=raw_data.get("isEquipped", False),
                owner=raw_data.get("owner")
            )
        # pylint: disable=invalid-name
        itemName = item_def.get("displayProperties", {}).get("name", "Unknown")
        itemType = item_def.get("itemTypeDisplayName", "Unknown")
        itemTier = item_def.get("inventory", {}).get("tierTypeName", "Unknown")
        stats = {}
        stats_def = item_def["stats"]["stats"]
        for stat_hash, stat_obj in stats_def.items():
            stat_def, _ = manifest_cache.resolve_manifest_hash(stat_hash)
            if stat_def and "displayProperties" in stat_def and "name" in stat_def["displayProperties"]:
                stat_name = stat_def["displayProperties"]["name"]
            else:
                stat_name = stat_hash
            stats[stat_name] = stat_obj.get("value")
        if item_instance_id:
            instance_info = cls._build_instance_info(item_instance_id, session_manager, manifest_cache)
            stats.update(instance_info.get("instanceStats", {}))
        return cls(
            itemHash=norm_hash,
            itemInstanceId=item_instance_id or raw_data.get("itemInstanceId"),
            itemName=itemName,
            itemType=itemType,
            itemTier=itemTier,
            stats=stats,
            location=raw_data.get("location"),
            isEquipped=raw_data.get("isEquipped", False),
            owner=raw_data.get("owner")
        )

    @staticmethod
    def _build_instance_info(
        item_instance_id: str,
        session_manager: BungieSessionManager,
        manifest_cache: ManifestCache
    ) -> dict:
        """
        Build instance-specific info for a Destiny 2 item.

        Args:
            item_instance_id (str): Destiny 2 item instance ID.
            manifest_cache (ManifestCache): ManifestCache instance for lookups.

        Returns:
            dict: Instance-specific item info including perks, stats, masterwork, and mods.
        """
        session = session_manager.get_session()
        access_token = session["access_token"]
        membership_id = session["membership_id"]
        headers_auth = {
            "Authorization": f"Bearer {access_token}",
            "X-API-Key": session_manager.api_key
        }
        # Try to get membership type
        profile_url = f"{session_manager.api_base}/User/GetMembershipsForCurrentUser/"
        profile_resp = retry_request(
            requests.get, profile_url, headers=headers_auth, timeout=session_manager.timeout)
        if not profile_resp.ok:
            return None
        profile_data = profile_resp.json()["Response"]
        if not profile_data.get("destinyMemberships"):
            return None
        membership_type = profile_data["destinyMemberships"][0].get(
            "membershipType", "1")
        # Fetch item instance data
        instance_url = f"{session_manager.api_base}/Destiny2/{membership_type}/Profile/{membership_id}/Item/{item_instance_id}/?components=300,302,304"
        instance_resp = retry_request(
            requests.get, instance_url, headers=headers_auth, timeout=session_manager.timeout)
        if not instance_resp.ok:
            return None
        instance_data = instance_resp.json()["Response"]

        info = {}
        inst_stats = instance_data["stats"]["data"]["stats"]
        if inst_stats:
            stats_instance = {}
            for stat_hash, stat_obj in inst_stats.items():
                stat_def, _ = manifest_cache.resolve_manifest_hash(stat_hash)
                stat_name = stat_def.get("displayProperties", {}).get("name", stat_hash) if stat_def else stat_hash
                stats_instance[stat_name] = stat_obj.get("value")
            info["instanceStats"] = stats_instance
        inst_sockets = instance_data.get("sockets", {}).get("socketEntries", [])
        perks_instance = []
        masterwork_instance = None
        mods_instance = []
        for socket in inst_sockets:
            plug_hash = socket.get("singleInitialItemHash")
            if plug_hash:
                plug_def, _ = manifest_cache.resolve_manifest_hash(plug_hash)
                if plug_def:
                    display_name = plug_def.get("itemTypeDisplayName", "").lower()
                    perks_instance.append({
                        "name": plug_def.get("displayProperties", {}).get("name", "Unknown"),
                        "description": plug_def.get("displayProperties", {}).get("description", ""),
                        "icon": plug_def.get("displayProperties", {}).get("icon", None),
                        "plugItemHash": plug_hash
                    })
                    if "masterwork" in display_name:
                        masterwork_instance = {
                            "name": plug_def.get("displayProperties", {}).get("name", "Unknown"),
                            "description": plug_def.get("displayProperties", {}).get("description", ""),
                            "icon": plug_def.get("displayProperties", {}).get("icon", None),
                            "plugItemHash": plug_hash
                        }
                    if "mod" in display_name:
                        mods_instance.append({
                            "name": plug_def.get("displayProperties", {}).get("name", "Unknown"),
                            "description": plug_def.get("displayProperties", {}).get("description", ""),
                            "icon": plug_def.get("displayProperties", {}).get("icon", None),
                            "plugItemHash": plug_hash
                        })
        if perks_instance:
            info["instancePerks"] = perks_instance
        if masterwork_instance:
            info["instanceMasterwork"] = masterwork_instance
        if mods_instance:
            info["instanceMods"] = mods_instance
        return info

class CharacterModel(BaseModel):
    """
    Pydantic model for a Destiny 2 character.

    Attributes:
        charId (str): Destiny 2 character ID.
        name (str): Character name.
        classType (str): Class type (Hunter, Titan, Warlock).
        items (List[ItemModel]): List of items for this character.
        data_version (Optional[datetime]): Bungie dateLastPlayed as datetime for freshness/version.
    """
    charId: str
    name: str
    classType: str
    items: List[ItemModel] = []
    data_version: Optional[datetime] = None

class VaultModel(BaseModel):
    """
    Pydantic model for the shared Destiny 2 vault.

    Attributes:
        items (List[ItemModel]): List of items in the shared vault.
        data_version (Optional[datetime]): Bungie dateLastPlayed as datetime for freshness/version.
    """
    items: List[ItemModel] = []
    data_version: Optional[datetime] = None

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
