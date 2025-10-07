"""
Helpers for mapping Destiny class, race, and gender names to their manifest hashes.

These utilities wrap ManifestCache so that the rest of the application can work with
canonical hash/name lookups without duplicating logic across modules.
"""
from functools import lru_cache
from typing import Dict, Tuple

from manifest_cache import ManifestCache

_DEFINITION_CLASS = "DestinyClassDefinition"
_DEFINITION_RACE = "DestinyRaceDefinition"
_DEFINITION_GENDER = "DestinyGenderDefinition"


def _build_maps(definition_type: str) -> Tuple[Dict[int, str], Dict[str, int]]:
    """
    Construct hash->name and name->hash dictionaries for the requested definition.

    Args:
        definition_type (str): Manifest definition table name.

    Returns:
        tuple: (hash_to_name, name_to_hash) dictionaries.
    """
    manifest = ManifestCache.instance()
    definitions = manifest.get_all_definitions(definition_type) or {}
    hash_to_name: Dict[int, str] = {}
    name_to_hash: Dict[str, int] = {}
    for hash_str, definition in definitions.items():
        name = (definition or {}).get("displayProperties", {}).get("name")
        if not name:
            continue
        try:
            hash_int = int(hash_str)
        except (TypeError, ValueError):
            continue
        hash_to_name[hash_int] = name
        name_to_hash[name] = hash_int
    return hash_to_name, name_to_hash


@lru_cache(maxsize=None)
def _class_maps() -> Tuple[Dict[int, str], Dict[str, int]]:
    return _build_maps(_DEFINITION_CLASS)


@lru_cache(maxsize=None)
def _race_maps() -> Tuple[Dict[int, str], Dict[str, int]]:
    return _build_maps(_DEFINITION_RACE)


@lru_cache(maxsize=None)
def _gender_maps() -> Tuple[Dict[int, str], Dict[str, int]]:
    return _build_maps(_DEFINITION_GENDER)


def class_hash_to_name() -> Dict[int, str]:
    """Return a copy of the class hash->name dictionary."""
    hash_map, _ = _class_maps()
    return hash_map.copy()


def class_name_to_hash() -> Dict[str, int]:
    """Return a copy of the class name->hash dictionary."""
    _, name_map = _class_maps()
    return name_map.copy()


def race_hash_to_name() -> Dict[int, str]:
    """Return a copy of the race hash->name dictionary."""
    hash_map, _ = _race_maps()
    return hash_map.copy()


def race_name_to_hash() -> Dict[str, int]:
    """Return a copy of the race name->hash dictionary."""
    _, name_map = _race_maps()
    return name_map.copy()


def gender_hash_to_name() -> Dict[int, str]:
    """Return a copy of the gender hash->name dictionary."""
    hash_map, _ = _gender_maps()
    return hash_map.copy()


def gender_name_to_hash() -> Dict[str, int]:
    """Return a copy of the gender name->hash dictionary."""
    _, name_map = _gender_maps()
    return name_map.copy()

