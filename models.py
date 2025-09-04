# pylint: disable=line-too-long, broad-exception-caught
"""
Models for Destiny 2 vault and character inventory management.

This module defines Pydantic models for API serialization and SQLAlchemy ORM models for database persistence.
Includes:
- ItemModel: Pydantic model for Destiny items, with manifest enrichment.
- CharacterModel, VaultModel: Pydantic models for character and vault containers.
- ORM models for SQL database schema.
"""
from datetime import datetime
from typing import Any, Dict, List, Optional

import requests
from pydantic import BaseModel
from sqlalchemy import (BigInteger, Boolean, Column, DateTime, ForeignKey,
                        ForeignKeyConstraint, Index, Integer, String, desc,
                        text)
from sqlalchemy.orm import declarative_base, relationship

from bungie_session_manager import BungieSessionManager
from helpers import retry_request
from manifest_cache import ManifestCache


# --- Pydantic Models ---
class ItemModel(BaseModel):
    """
    Pydantic model for a Destiny 2 item.

    Attributes:
        itemHash (int): Destiny 2 item hash (unique identifier).
        itemInstanceId (Optional[str]): Instance ID for the item (if applicable).
        itemName (str): Display name of the item.
        itemType (str): Type of item (e.g., weapon, armor).
        itemTier (Optional[str]): Tier of item (e.g., Legendary, Exotic).
        stats (Dict[str, int]): Stat values for the item.
        perks (Dict[str, List[Dict[str, Any]]]): Perks and socket/plugs for the item.
        energy (Optional[Dict[str, Any]]): Energy details for armor items.
        sockets (Optional[List[Dict[str, Any]]]): Socket details for the item.
        sandboxPerks (Optional[List[Dict[str, Any]]]): Artifact/passive perks.
        location (Optional[int]): Where the item is stored (vault, character).
        isEquipped (bool): Whether the item is currently equipped.
        owner (Optional[str]): Owner of the item (character ID or vault).
    """

    # Instance data
    itemHash: int
    itemInstanceId: Optional[str]
    itemName: str
    itemType: str
    itemTier: Optional[str]
    stats: Dict[str, int] = dict()  # noqa: RUF012
    perks: Dict[str, List[Dict[str, Any]]] = dict()
    energy: Optional[Dict[str, Any]] = None  # {type_hash, type_name, capacity, used, unused}
    sockets: Optional[List[Dict[str, Any]]] = None  # list of {index, visible, enabled, equipped{name,hash,icon}}
    sandboxPerks: Optional[List[Dict[str, Any]]] = None  # 302 perks (artifact/passives)
    location: Optional[int]
    isEquipped: bool = False
    owner: Optional[str]

    @staticmethod
    def _extract_stats(stats_data, manifest_cache):
        """
        Extract stats from a stats dict using manifest_cache for name resolution.
        """
        stats = {}
        for stat_hash, stat_obj in (stats_data or {}).items():
            stat_def, _ = manifest_cache.resolve_manifest_hash(stat_hash, ["DestinyStatDefinition"])
            stat_name = (stat_def or {}).get("displayProperties", {}).get("name") or str(stat_hash)
            stats[stat_name] = stat_obj.get("value")
        return stats

    @staticmethod
    def _extract_energy(energy_data, manifest_cache):
        """
        Extract energy details from energy_data using manifest_cache for type name.
        """
        if not energy_data:
            return None
        et_hash = energy_data.get("energyTypeHash")
        et_def, _ = manifest_cache.resolve_manifest_hash(et_hash, ["DestinyEnergyTypeDefinition"]) if et_hash is not None else (None, None)
        return {
            "type_hash": et_hash,
            "type_name": (et_def or {}).get("displayProperties", {}).get("name"),
            "capacity": energy_data.get("energyCapacity"),
            "used": energy_data.get("energyUsed"),
            "unused": energy_data.get("energyUnused"),
        }

    @staticmethod
    def _extract_sandbox_perks(perks_data, manifest_cache):
        """
        Extract sandbox perks from perks_data using manifest_cache for name/icon.
        """
        sp_list = []
        for p in perks_data or []:
            s_hash = p.get("perkHash")
            if not s_hash:
                continue
            s_def, _ = manifest_cache.resolve_manifest_hash(s_hash, ["DestinySandboxPerkDefinition"])
            dp = (s_def or {}).get("displayProperties", {})
            sp_list.append({
                "hash": s_hash,
                "name": dp.get("name", str(s_hash)),
                "icon": dp.get("icon"),
                "active": p.get("isActive", False),
                "visible": p.get("visible", False),
            })
        return sp_list

    @staticmethod
    def _extract_sockets(sockets_data, manifest_cache):
        """
        Extract sockets from sockets_data using manifest_cache for plug info.
        """
        sockets_out = []
        for idx, s in enumerate(sockets_data or []):
            plug_hash = s.get("plugHash")
            plug = None
            if plug_hash is not None:
                p_def, _ = manifest_cache.resolve_manifest_hash(plug_hash, ["DestinyInventoryItemDefinition"])
                dp = (p_def or {}).get("displayProperties", {})
                plug = {"hash": plug_hash, "name": dp.get("name", str(plug_hash)), "icon": dp.get("icon")}
            sockets_out.append({
                "socketIndex": idx,
                "isEnabled": s.get("isEnabled", False),
                "isVisible": s.get("isVisible", False),
                "equipped": plug,
            })
        return sockets_out

    @staticmethod
    def _extract_reusable_plugs(reusable_plugs_data, manifest_cache):
        """
        Extract reusable plugs from reusable_plugs_data using manifest_cache for plug info.
        """
        rp = reusable_plugs_data or {}
        result = []
        for idx_str, plugs in rp.items():
            try:
                idx = int(idx_str)
            except Exception:
                continue
            choices = []
            for p in plugs or []:
                h = p.get("plugItemHash")
                if h is None:
                    continue
                d, _ = manifest_cache.resolve_manifest_hash(h, ["DestinyInventoryItemDefinition"])
                dp = (d or {}).get("displayProperties", {})
                choices.append({"hash": h, "name": dp.get("name", str(h)), "icon": dp.get("icon")})
            if choices:
                result.append({"socketIndex": idx, "choices": choices})
        return result

    @classmethod
    def from_components(
        cls,
        raw_item: dict,
        components: Optional[dict] = None,
    ) -> "ItemModel":
        """
        Build an ItemModel from an item's raw definition snippet and optional pre-fetched instance components (300/302/304/305/310).
        Uses ManifestCache and BungieSessionManager singletons internally; does not require them as parameters.
        """
        manifest_cache = ManifestCache.instance()
        item_hash = raw_item.get("itemHash")
        item_def, _ = manifest_cache.resolve_manifest_hash(item_hash, ["DestinyInventoryItemDefinition"])
        item_name = (item_def or {}).get("displayProperties", {}).get("name", "Unknown")
        item_type = (item_def or {}).get("itemTypeDisplayName", "Unknown")
        item_tier = (item_def or {}).get("inventory", {}).get("tierTypeName", "Unknown")

        stats = cls._extract_stats((item_def or {}).get("stats", {}).get("stats", {}), manifest_cache)
        perks: Dict[str, List[Dict[str, Any]]] = dict()

        if components:
            # 300 energy
            inst = (components.get("instance") or {}).get("data", {})
            energy = cls._extract_energy(inst.get("energy"), manifest_cache)
            if energy:
                perks["energy"] = [energy]
            # 304 stats
            stats.update(cls._extract_stats((components.get("stats") or {}).get("data", {}).get("stats", {}), manifest_cache))
            # 302 sandbox perks
            sp_list = cls._extract_sandbox_perks((components.get("perks") or {}).get("data", {}).get("perks", []), manifest_cache)
            if sp_list:
                perks["sandboxPerks"] = sp_list
            # 305 sockets
            sockets_out = cls._extract_sockets((components.get("sockets") or {}).get("data", {}).get("sockets", []), manifest_cache)
            if sockets_out:
                perks["sockets"] = sockets_out
            # 310 reusable plugs
            rp = ((components.get("reusablePlugs") or {}).get("data", {}) or {}).get("plugs", {})
            ro_list = cls._extract_reusable_plugs(rp, manifest_cache)
            if ro_list:
                perks["reusablePlugs"] = ro_list

        # If no components provided, fetch instance info using singleton managers
        if not components and raw_item.get("itemInstanceId"):
            session_manager = BungieSessionManager.instance()
            inst_info = cls._build_instance_info(raw_item.get("itemInstanceId"), session_manager, manifest_cache)
            stats.update(inst_info.get("instanceStats", {}))
            if "energy" in inst_info:
                perks["energy"] = [inst_info["energy"]]
            if "instanceSockets" in inst_info:
                perks["sockets"] = inst_info["instanceSockets"]
            if "sandboxPerks" in inst_info:
                perks["sandboxPerks"] = inst_info["sandboxPerks"]
            if "reusablePlugs" in inst_info:
                perks["reusablePlugs"] = inst_info["reusablePlugs"]

        return cls(
            itemHash=item_hash,
            itemInstanceId=raw_item.get("itemInstanceId"),
            itemName=item_name,
            itemType=item_type,
            itemTier=item_tier,
            stats=stats,
            perks=perks,
            location=raw_item.get("location"),
            isEquipped=raw_item.get("isEquipped", False),
            owner=raw_item.get("owner"),
        )

    @classmethod
    def from_components_batched(
        cls,
        raw_item: dict,
        plug_defs: Dict[str, Dict[str, Any]],
        sandbox_defs: Dict[str, Dict[str, Any]],
        item_components: Optional[dict] = None,
    ) -> "ItemModel":
        """
        Build ItemModel using pre-resolved definition maps (batched).
        Uses ManifestCache singleton internally; does not require it as a parameter.
        Args:
            plug_defs (Dict[str, Dict[str, Any]]): Pre-resolved plug definitions.
            sandbox_defs (Dict[str, Dict[str, Any]]): Pre-resolved sandbox perk definitions.
            item_components (Optional[dict]): Item instance components.
        """
        manifest_cache = ManifestCache.instance()
        item_hash = raw_item.get("itemHash")
        item_name = "Unknown"
        item_type = "Unknown"
        item_tier = None
        item_def, _ = manifest_cache.resolve_manifest_hash(item_hash, ["DestinyInventoryItemDefinition"])
        if item_def:
            item_name = item_def.get("displayProperties", {}).get("name", item_name)
            item_type = item_def.get("itemTypeDisplayName", item_type)
            item_tier = item_def.get("inventory", {}).get("tierTypeName", None)

        stats: Dict[str, int] = dict()
        perks: Dict[str, List[Dict[str, Any]]] = dict()

        if item_components:
            # 304 stats
            stats.update(cls._extract_stats((item_components.get("stats") or {}).get("data", {}).get("stats", {}), manifest_cache))
            # 300 energy
            inst = (item_components.get("instance") or {}).get("data", {})
            energy = cls._extract_energy(inst.get("energy"), manifest_cache)
            if energy:
                perks["energy"] = [energy]
            # 302 sandbox perks
            sps = []
            for p in ((item_components.get("perks") or {}).get("data", {}).get("perks", []) or []):
                h = p.get("perkHash")
                if h is None:
                    continue
                d = sandbox_defs.get(str(int(h) & 0xFFFFFFFF), {})
                dp = (d or {}).get("displayProperties", {})
                sps.append({
                    "hash": h,
                    "name": dp.get("name", str(h)),
                    "icon": dp.get("icon"),
                    "active": p.get("isActive", False),
                    "visible": p.get("visible", False),
                })
            if sps:
                perks["sandboxPerks"] = sps
            # 305 sockets
            sock_out = []
            for idx, s in enumerate(((item_components.get("sockets") or {}).get("data", {}).get("sockets", []) or [])):
                h = s.get("plugHash")
                plug = None
                if h is not None:
                    d = plug_defs.get(str(int(h) & 0xFFFFFFFF), {})
                    dp = (d or {}).get("displayProperties", {})
                    plug = {"hash": h, "name": dp.get("name", str(h)), "icon": dp.get("icon")}
                sock_out.append({
                    "socketIndex": idx,
                    "isEnabled": s.get("isEnabled", False),
                    "isVisible": s.get("isVisible", False),
                    "equipped": plug,
                })
            if sock_out:
                perks["sockets"] = sock_out
            # 310 reusable plugs (choices per socket) using pre-resolved plug defs
            rp = ((item_components.get("reusablePlugs") or {}).get("data", {}) or {}).get("plugs", {})
            result = []
            for idx_str, plugs in rp.items():
                try:
                    idx = int(idx_str)
                except Exception:
                    continue
                choices = []
                for p in plugs or []:
                    h = p.get("plugItemHash")
                    if h is None:
                        continue
                    d = plug_defs.get(str(int(h) & 0xFFFFFFFF), {})
                    dp = (d or {}).get("displayProperties", {})
                    choices.append({"hash": h, "name": dp.get("name", str(h)), "icon": dp.get("icon")})
                if choices:
                    result.append({"socketIndex": idx, "choices": choices})
            if result:
                perks["reusablePlugs"] = result

        return cls(
            itemHash=item_hash,
            itemInstanceId=raw_item.get("itemInstanceId"),
            itemName=item_name,
            itemType=item_type,
            itemTier=item_tier,
            stats=stats,
            perks=perks,
            location=raw_item.get("location"),
            isEquipped=raw_item.get("isEquipped", False),
            owner=raw_item.get("owner"),
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
            session_manager (BungieSessionManager): Bungie session manager for API calls.
            manifest_cache (ManifestCache): ManifestCache instance for lookups.

        Returns:
            dict: Instance-specific item info including perks, stats, masterwork, and mods.
        """
        session = session_manager.get_session()
        access_token = session.get("access_token")
        membership_id = session.get("membership_id")
        membership_type = session.get("membership_type")
        if not membership_id or not membership_type or not access_token:
            return {}
        headers_auth = {
            "Authorization": f"Bearer {access_token}",
            "X-API-Key": session_manager.api_key,
        }

        instance_url = (
            f"{session_manager.api_base}/Destiny2/{membership_type}/Profile/"
            f"{membership_id}/Item/{item_instance_id}/?components=300,302,304,305,310"
        )
        instance_resp = retry_request(requests.get, instance_url, headers=headers_auth, timeout=session_manager.timeout)
        if not instance_resp.ok:
            return {}
        instance_data = instance_resp.json().get("Response", {})

        info: Dict[str, Any] = {}

        # 300 — energy (armor) & basic equip flags if present
        inst = instance_data.get("instance", {}).get("data", {})
        energy = ItemModel._extract_energy(inst.get("energy"), manifest_cache)
        if energy:
            info["energy"] = energy

        # 304 — instance stats (names resolved)
        inst_stats = instance_data.get("stats", {}).get("data", {}).get("stats", {})
        if inst_stats:
            info["instanceStats"] = ItemModel._extract_stats(inst_stats, manifest_cache)

        # 302 — sandbox perks (artifact/passives)
        sp_list = ItemModel._extract_sandbox_perks(instance_data.get("perks", {}).get("data", {}).get("perks", []), manifest_cache)
        if sp_list:
            info["sandboxPerks"] = sp_list

        # 305 — sockets: equipped plugs only (no 310 here)
        sockets = ItemModel._extract_sockets(instance_data.get("sockets", {}).get("data", {}).get("sockets", []), manifest_cache)
        if sockets:
            info["instanceSockets"] = sockets

        # 310 — reusable plugs: all candidate plugs available per socket for this instance
        reusable_plugs = instance_data.get("reusablePlugs", {}).get("data", {}).get("plugs", {})
        ro_list = ItemModel._extract_reusable_plugs(reusable_plugs, manifest_cache)
        if ro_list:
            info["reusablePlugs"] = ro_list

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
    items: List[ItemModel] = list()
    data_version: Optional[datetime] = None

    @classmethod
    def from_components(
        cls,
        character_blob: dict,
        items_raw: List[dict],
        components_by_instance: Dict[str, dict],
    ) -> "CharacterModel":
        """
        Build a CharacterModel from a character blob, raw items, and a mapping of instanceId->components (300/302/304/305).
        Uses ManifestCache singleton internally; does not require it as a parameter.
        """
        char_id = str(character_blob.get("characterId"))
        name = character_blob.get("displayName") or char_id
        class_type = character_blob.get("classTypeLabel") or str(character_blob.get("classType"))

        items: List[ItemModel] = []
        for it in items_raw:
            iid = it.get("itemInstanceId")
            comps = components_by_instance.get(str(iid)) if iid else None
            items.append(ItemModel.from_components(it, components=comps))
        return cls(charId=char_id, name=name, classType=class_type, items=items)

class VaultModel(BaseModel):
    """
    Pydantic model for the shared Destiny 2 vault.

    Attributes:
        items (List[ItemModel]): List of items in the shared vault.
        data_version (Optional[datetime]): Bungie dateLastPlayed as datetime for freshness/version.
    """
    items: List[ItemModel] = list()
    data_version: Optional[datetime] = None

    @classmethod
    def from_components(
        cls,
        items_raw: List[dict],
        components_by_instance: Dict[str, dict],
    ) -> "VaultModel":
        """
        Build a VaultModel from raw items and a mapping of instanceId->components (300/302/304/305).
        Uses ManifestCache singleton internally; does not require it as a parameter.
        """
        items: List[ItemModel] = []
        for it in items_raw:
            iid = it.get("itemInstanceId")
            comps = components_by_instance.get(str(iid)) if iid else None
            items.append(ItemModel.from_components(it, components=comps))
        return cls(items=items)

# --- SQLAlchemy ORM Models ---

Base = declarative_base()

class User(Base):
    """
    SQLAlchemy ORM model representing a Destiny 2 user/account.
    """
    __tablename__ = 'Users'
    user_id = Column(BigInteger, primary_key=True)
    membership_id = Column(String(50), nullable=False)
    membership_type = Column(String(20), nullable=False)
    display_name = Column(String(100))
    created_at = Column(DateTime, nullable=False, server_default=text("SYSUTCDATETIME()"))
    characters = relationship("Character", back_populates="user")

class Character(Base):
    """
    SQLAlchemy ORM model representing a Destiny 2 character belonging to a user.
    """
    __tablename__ = 'Characters'
    character_id = Column(BigInteger, primary_key=True)
    user_id = Column(BigInteger, ForeignKey('Users.user_id'), nullable=False)
    class_type = Column(String(50))
    light = Column(Integer)
    race_hash = Column(BigInteger)
    created_at = Column(DateTime, nullable=False, server_default=text("SYSUTCDATETIME()"))
    user = relationship("User", back_populates="characters")
    items = relationship("Item", back_populates="character")
    __table_args__ = (Index('IX_Characters_UserId', 'user_id'),)

class Item(Base):
    """
    SQLAlchemy ORM model representing an inventory item for a character.
    """
    __tablename__ = 'Items'
    item_id = Column(BigInteger, primary_key=True)
    character_id = Column(BigInteger, ForeignKey('Characters.character_id'))
    item_hash = Column(BigInteger, nullable=False)
    item_instance_id = Column(BigInteger)
    name = Column(String(100))
    type = Column(String(50))
    tier = Column(String(50))
    power_value = Column(Integer)
    is_equipped = Column(Boolean, nullable=False, server_default=text("0"))
    content_hash = Column(String(64))
    collectible_hash = Column(BigInteger)
    power_cap_hash = Column(BigInteger)
    season_hash = Column(BigInteger)
    updated_at = Column(DateTime, nullable=False, server_default=text("SYSUTCDATETIME()"))
    created_at = Column(DateTime, nullable=False, server_default=text("SYSUTCDATETIME()"))
    character = relationship("Character", back_populates="items")
    stats = relationship("ItemStat", back_populates="item")
    sockets = relationship("ItemSocket", back_populates="item")
    __table_args__ = (
        Index('IX_Items_Character_Equipped', 'character_id', 'is_equipped'),
        Index('IX_Items_ItemHash', 'item_hash'),
        Index('IX_Items_InstanceId', 'item_instance_id'),
    )

class ItemStat(Base):
    """
    SQLAlchemy ORM model representing a stat value for an item (e.g., Discipline, Mobility).
    """
    __tablename__ = 'ItemStats'
    item_id = Column(BigInteger, ForeignKey('Items.item_id'), primary_key=True)
    stat_hash = Column(BigInteger, primary_key=True)
    stat_name = Column(String(100))
    stat_value = Column(Integer, nullable=False)
    item = relationship("Item", back_populates="stats")
    __table_args__ = (
        Index('IX_ItemStats_StatHash_Value', 'stat_hash', desc('stat_value')),
        Index('IX_ItemStats_ItemId', 'item_id'),
    )


class ItemSocket(Base):
    """
    SQLAlchemy ORM model representing a socket on an item for customization.
    """
    __tablename__ = 'ItemSockets'
    item_id = Column(BigInteger, ForeignKey('Items.item_id'), primary_key=True)
    socket_index = Column(Integer, primary_key=True)
    socket_type_hash = Column(BigInteger)
    category_name = Column(String(100))
    is_visible = Column(Boolean, nullable=False, server_default=text("1"))
    is_enabled = Column(Boolean, nullable=False, server_default=text("1"))
    item = relationship("Item", back_populates="sockets")
    plugs = relationship("ItemPlug", back_populates="socket")
    __table_args__ = (
        Index('IX_ItemSockets_ItemId', 'item_id'),
    )

class ItemPlug(Base):
    """
    SQLAlchemy ORM model representing a plug (perk/mod) in a socket, tracks equipped state.
    Composite FK to ItemSockets (item_id, socket_index).
    """
    __tablename__ = 'ItemPlugs'
    item_id = Column(BigInteger, primary_key=True)
    socket_index = Column(Integer, primary_key=True)
    plug_hash = Column(BigInteger, primary_key=True)
    plug_name = Column(String(100))
    plug_icon = Column(String(255))
    is_equipped = Column(Boolean, nullable=False, server_default=text("0"))
    __table_args__ = (
        ForeignKeyConstraint(
            ["item_id", "socket_index"],
            ["ItemSockets.item_id", "ItemSockets.socket_index"],
            name="fk_itemplugs_itemsockets"
        ),
        Index('IX_ItemPlugs_ItemId', 'item_id'),
        Index('IX_ItemPlugs_SocketIndex', 'socket_index'),
        Index('IX_ItemPlugs_PlugHash', 'plug_hash'),
    )
    socket = relationship("ItemSocket", back_populates="plugs")

# --- Additional ORM classes for missing schema tables ---

class ItemSocketChoice(Base):
    """
    SQLAlchemy ORM model representing a choice of plug for a socket instance.
    """
    __tablename__ = 'ItemSocketChoices'
    instance_id = Column(BigInteger, primary_key=True)
    socket_index = Column(Integer, primary_key=True)
    plug_hash = Column(BigInteger, primary_key=True)
    plug_name = Column(String(100))
    __table_args__ = (
        Index('IX_ItemSocketChoices_Plug', 'plug_hash'),
        Index('IX_ItemSocketChoices_Inst', 'instance_id'),
    )

class ItemSandboxPerk(Base):
    """
    SQLAlchemy ORM model representing a sandbox perk for an item instance.
    """
    __tablename__ = 'ItemSandboxPerks'
    instance_id = Column(BigInteger, primary_key=True)
    sandbox_perk_hash = Column(BigInteger, primary_key=True)
    name = Column(String(100))
    icon = Column(String(255))
    is_active = Column(Boolean, nullable=False, server_default=text('0'))
    is_visible = Column(Boolean, nullable=False, server_default=text('0'))
    __table_args__ = (
        Index('IX_ItemSandboxPerks_Hash', 'sandbox_perk_hash'),
        Index('IX_ItemSandboxPerks_Inst', 'instance_id'),
    )

class ItemEnergy(Base):
    """
    SQLAlchemy ORM model representing energy details for an item instance.
    """
    __tablename__ = 'ItemEnergy'
    instance_id = Column(BigInteger, primary_key=True)
    energy_type_hash = Column(BigInteger)
    energy_type_name = Column(String(50))
    capacity = Column(Integer)
    used = Column(Integer)
    unused = Column(Integer)

class ItemSocketLayout(Base):
    """
    SQLAlchemy ORM model representing the layout of sockets for an item hash.
    """
    __tablename__ = 'ItemSocketLayout'
    item_hash = Column(BigInteger, primary_key=True)
    socket_index = Column(Integer, primary_key=True)
    category_name = Column(String(100))
    __table_args__ = (
        Index('IX_ItemSocketLayout_ItemHash', 'item_hash'),
    )
