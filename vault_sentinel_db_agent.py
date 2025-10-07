#pylint: disable=broad-except, invalid-name, line-too-long
"""
Vault Sentinel DB Agent for Azure AI
------------------------------------
Implements a secure, schema-compliant agent that processes Destiny 2 gear queries using Azure AI. 
All queries must conform to the embedded schema. Uses Managed Identity for authentication and follows 
Azure best practices for reliability, security, and performance.
"""


import json
import logging
import re
import threading
import time
import urllib.parse
from typing import Any, Dict

import pyodbc

from openai import AzureOpenAI
from sqlalchemy import create_engine, orm, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.exc import TimeoutError as SaTimeoutError
from sqlalchemy.pool import NullPool

from constants import (
    OPENAI_API_KEY, OPENAI_API_VERSION, OPENAI_DEPLOYMENT,
    OPENAI_ENDPOINT, SQL_DATABASE, SQL_DRIVER, SQL_SERVER,
    SQL_USER, SQL_PASSWORD, SQL_DISABLE_ODBC_POOLING
)
from helpers import compute_hash
from models import (
    Character,
    Item,
    ItemEnergy,
    ItemPlug,
    ItemSandboxPerk,
    ItemSocket,
    ItemSocketChoice,
    ItemStat,
    User,
    Vault,
)
from manifest_identity import race_name_to_hash


class VaultSentinelDBAgent:
    """
    Business logic agent for Destiny 2 gear queries, designed for use in Azure Function App endpoints.
    Implements schema validation and core query processing logic with Azure SQL cold start mitigation.
    """

    _instance = None

    @classmethod
    def instance(cls) -> "VaultSentinelDBAgent":
        """Thread-safe singleton factory for the DB agent."""
        if not hasattr(cls, "_instance_lock"):
            cls._instance_lock = threading.RLock()
        if cls._instance is None:
            with cls._instance_lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        """Reset the singleton instance (useful for tests)."""
        if hasattr(cls, "_instance_lock"):
            with cls._instance_lock:
                cls._instance = None
        else:
            cls._instance = None

    @classmethod
    def is_db_configured(cls) -> bool:
        """Quick check to see if minimal DB config constants are set without constructing the agent."""
        return bool(SQL_SERVER and SQL_DATABASE and SQL_DRIVER)

    def __init__(self):
        logging.info("VaultSentinelDBAgent initialized.")
        # Azure OpenAI Chat Completions client
        self.chat_client = None
        if OPENAI_ENDPOINT:
            self.chat_client = AzureOpenAI(
                azure_endpoint=OPENAI_ENDPOINT,
                azure_deployment=OPENAI_DEPLOYMENT,
                api_key=OPENAI_API_KEY,
                api_version=OPENAI_API_VERSION
            )
            logging.info("Connected to Azure OpenAI Chat Completions.")

        # SQLAlchemy engine and sessionmaker for ORM persistence
        self.engine = None
        self.Session = None
        self._connection_warmed = False
        self._initialize_database_connection()

    def _initialize_database_connection(self):
        """Initialize database connection optimized for Azure SQL Database cold starts."""
        if not (SQL_SERVER and SQL_DATABASE and SQL_DRIVER):
            logging.error("SQL_SERVER, SQL_DATABASE, or SQL_DRIVER constant not set.")
            return

        # Choose authentication method: SQL auth if user/password, else Managed Identity
        pooling_segment = "Pooling=no;" if SQL_DISABLE_ODBC_POOLING else ""
        if SQL_DISABLE_ODBC_POOLING:
            try:
                pyodbc.pooling = False
            except Exception as exc:  # pragma: no cover - defensive
                logging.warning("Failed to disable pyodbc pooling: %s", exc)
        if SQL_USER and SQL_PASSWORD:
            logging.debug(
                "SQL auth credentials loaded (user=%s, password_len=%s)",
                SQL_USER,
                len(SQL_PASSWORD) if SQL_PASSWORD else 0,
            )
            # Use the exact ODBC connection string as in the working test, URL-encoded for SQLAlchemy
            odbc_str = (
                f"DRIVER={{{SQL_DRIVER}}};"
                f"SERVER={SQL_SERVER};"
                f"DATABASE={SQL_DATABASE};"
                f"UID={SQL_USER};"
                f"PWD={SQL_PASSWORD};"
                "Encrypt=yes;"
                "TrustServerCertificate=no;"
                "Connection Timeout=30;"
                f"{pooling_segment}"
            )
            sqlalchemy_url = "mssql+pyodbc:///?odbc_connect=" + urllib.parse.quote_plus(odbc_str)
            logging.info("Using SQL authentication for database connection.")
        else:
            odbc_str = (
                f"DRIVER={{{SQL_DRIVER}}};"
                f"SERVER={SQL_SERVER};"
                f"DATABASE={SQL_DATABASE};"
                "authentication=ActiveDirectoryMsi;"
                "Encrypt=yes;"
                "TrustServerCertificate=no;"
                "Connection Timeout=30;"
                f"{pooling_segment}"
            )
            sqlalchemy_url = "mssql+pyodbc:///?odbc_connect=" + urllib.parse.quote_plus(odbc_str)
            logging.info("Using Managed Identity for database connection.")

        # Engine configuration optimized for Azure SQL cold starts
        connect_kwargs = {
            "timeout": 60,
            "autocommit": False,
        }

        try:
            if SQL_DISABLE_ODBC_POOLING:
                self.engine = create_engine(
                    "mssql+pyodbc://",
                    poolclass=NullPool,
                    echo=False,
                    creator=lambda: pyodbc.connect(odbc_str, **connect_kwargs),
                )
            else:
                engine_config = {
                    "pool_pre_ping": True,
                    "pool_recycle": 1800,
                    "pool_timeout": 60,
                    "max_overflow": 5,
                    "pool_size": 2,
                    "echo": False,
                    "connect_args": connect_kwargs,
                }
                self.engine = create_engine(sqlalchemy_url, **engine_config)
            self.Session = orm.sessionmaker(bind=self.engine)
            logging.info("SQLAlchemy engine/session initialized for Azure SQL DB.")
            # Attempt connection warmup in background
            self._warmup_connection()
        except Exception as e:
            logging.error("Failed to initialize SQLAlchemy engine: %s", e)
            self.engine = None
            self.Session = None

    def _warmup_connection(self):
        """Warm up the database connection to mitigate cold start issues."""
        if not self.Session:
            return
            
        max_warmup_attempts = 3
        warmup_delay = 2
        
        for attempt in range(max_warmup_attempts):
            try:
                session = self.Session()
                try:
                    # Simple warmup query with extended timeout
                    warm_val = session.execute(text("SELECT 1 as warmup")).scalar()
                    if warm_val == 1:
                        self._connection_warmed = True
                        logging.info("Database connection warmed up successfully.")
                        return
                finally:
                    session.close()
                    
            except (OperationalError, SaTimeoutError) as e:
                logging.warning(
                    "Database warmup attempt %d/%d failed (expected for cold start): %s", 
                    attempt + 1, max_warmup_attempts, str(e)
                )
                if attempt < max_warmup_attempts - 1:
                    time.sleep(warmup_delay)
                    warmup_delay *= 2
            except Exception as e:
                logging.error("Unexpected error during database warmup: %s", e)
                break
        
        logging.warning("Database warmup incomplete - connection may experience cold start delays.")

    def _get_session_with_cold_start_handling(self):
        """Get a database session with Azure SQL cold start mitigation."""
        if not self.Session:
            raise RuntimeError("Database session not available")
        
        max_attempts = 5 if not self._connection_warmed else 3
        base_delay = 2
        
        session = None
        for attempt in range(max_attempts):
            try:
                session = self.Session()
                
                # Test the session with a lightweight query
                session.execute(text("SELECT 1")).scalar()
                return session
                
            except (OperationalError, SaTimeoutError) as e:
                if session:
                    session.close()
                
                # Check if this looks like a cold start issue
                error_msg = str(e).lower()
                cold_start_indicators = [
                    'login timeout',
                    'connection timeout',
                    'hyt00',
                    'server is not ready',
                    'database is starting',
                    'not currently available',
                    '40613',
                ]
                is_cold_start = any(indicator in error_msg for indicator in cold_start_indicators)
                
                if is_cold_start and attempt < max_attempts - 1:
                    delay = base_delay * (2 ** attempt)
                    logging.warning(
                        "Cold start detected on attempt %d/%d, retrying in %d seconds: %s", 
                        attempt + 1, max_attempts, delay, str(e)
                    )
                    time.sleep(delay)
                    continue
                else:
                    raise RuntimeError(f"Database session failed after {attempt + 1} attempts: {e}") from e
                    
            except Exception as e:
                if session:
                    session.close()
                raise RuntimeError(f"Unexpected database error: {e}") from e
        
        raise RuntimeError(f"Failed to create database session after {max_attempts} attempts")

    def validate_query(self, query: Dict[str, Any]) -> bool:
        """
        Validate query against the embedded schema and ensure no required key is None/null or empty if a data structure.
        """
        required_keys = ["intent", "filters", "output", "sort", "limit"]
        for key in required_keys:
            if key not in query:
                logging.error("Missing required key: %s", key)
                return False
            if query[key] is None:
                logging.error("Key '%s' must not be null.", key)
                return False
            # If the key is a dict, it must not be empty
            if isinstance(query[key], dict) and not query[key]:
                logging.error("Key '%s' must not be an empty dict.", key)
                return False
        if not isinstance(query["intent"], str):
            logging.error("'intent' must be a string.")
            return False
        if not isinstance(query["filters"], dict):
            logging.error("'filters' must be a dict.")
            return False
        if not isinstance(query["output"], dict):
            logging.error("'output' must be a dict.")
            return False
        if not isinstance(query["sort"], dict):
            logging.error("'sort' must be a dict.")
            return False
        if not isinstance(query["limit"], int):
            logging.error("'limit' must be an int.")
            return False
        return True


    def process_query(self, query: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main business logic for processing Destiny 2 gear queries.
        Uses AI to generate SQL, executes it via SQLAlchemy, and returns results.
        """
        if not self.validate_query(query):
            raise ValueError("Query does not conform to schema.")
        logging.info("Processing query: %s", query["intent"])

        if not self.Session:
            logging.error("SQLAlchemy sessionmaker not initialized.")
            return {"status": "error", "error": "Sessionmaker not initialized"}

        if self.chat_client is None:
            logging.error("Azure OpenAI client is not configured. Set AZURE_OPENAI_* settings.")
            return {"status": "error", "error": "Azure OpenAI not configured."}

        # Get instructions for the AI
        with open("db-agent-instructions.md", "r", encoding="utf-8") as f:
            instructions = f.read()

        system_message = {
            "role": "system",
            "content": instructions
        }
        user_message = {
            "role": "user",
            "content": json.dumps(query, indent=2)
        }

        try:
            response = self.chat_client.chat.completions.create(
                model=OPENAI_DEPLOYMENT,
                messages=[system_message, user_message],
                temperature=0.0,
                frequency_penalty=0.0,
                presence_penalty=-2.0
            )
            sql_query = response.choices[0].message.content.strip() if response.choices else ""
            logging.info("AI-generated SQL: %s", sql_query)
            valid, reason = self._validate_sql(sql_query)
            if not valid:
                logging.error("Rejected AI SQL: %s", reason)
                return {"status": "error", "error": f"Rejected SQL: {reason}"}

            session = self._get_session_with_cold_start_handling()
            try:
                query_result = session.execute(text(sql_query))
                rows = query_result.fetchall()
                columns = query_result.keys()
                data = [dict(zip(columns, row)) for row in rows]
                return {"status": "success", "data": data, "sql": sql_query}
            finally:
                session.close()
                
        except Exception as e:
            logging.error("process_query failed: %s", e)
            return {"status": "error", "error": str(e)}

    # --- SQL Validation ---
    _ALLOWED_TABLES = {
        'users', 'vaults', 'characters', 'items', 'itemstats', 'itemsockets',
        'itemplugs', 'itemsocketchoices', 'itemsandboxperks', 'itemenergy', 'itemsocketlayout'
    }

    _FORBIDDEN_KEYWORDS = {
        'insert', 'update', 'delete', 'drop', 'alter', 'create', 'exec', 'execute',
        'merge', 'grant', 'revoke', 'truncate', 'sp_', 'xp_'
    }

    def _validate_sql(self, sql_query: str) -> tuple[bool, str]:
        q = (sql_query or '').strip()
        if not q:
            return False, 'empty query'
        ql = q.lower()
        if not ql.startswith('select'):
            return False, 'must be a SELECT query'
        if len(q) > 8000:
            return False, 'query too long'
        # disallow multi-statements and comments
        if ';' in ql:
            return False, 'multiple statements not allowed'
        if '--' in ql or '/*' in ql or '*/' in ql:
            return False, 'comments not allowed'
        # forbid dangerous keywords
        for kw in self._FORBIDDEN_KEYWORDS:
            if re.search(rf"\b{re.escape(kw)}\b", ql):
                return False, f'forbidden keyword: {kw}'
        # Extract table identifiers after FROM and JOIN and validate
        def base_table(name: str) -> str:
            # strip schema and brackets: dbo.[Items] -> items
            n = name.strip()
            n = n.strip('[]')
            if '.' in n:
                n = n.split('.')[-1]
            return n.lower()
        for token in re.findall(r"\bfrom\s+([\w\[\]\.]+)|\bjoin\s+([\w\[\]\.]+)", ql):
            cand = token[0] or token[1]
            if not cand:
                continue
            tbl = base_table(cand)
            # allow aliases like items i => we already captured just the first name
            if tbl not in self._ALLOWED_TABLES:
                return False, f'unknown or disallowed table: {tbl}'
        return True, 'ok'

    @staticmethod
    def _safe_int(value: Any) -> int | None:
        """Convert a value to int when possible, returning None on failure."""
        if value is None:
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            try:
                return int(str(value))
            except (TypeError, ValueError):
                return None

    def _get_or_create_user(self, session, membership_id: str, membership_type: str) -> User:
        user_obj = session.query(User).filter_by(membership_id=membership_id).first()
        if not user_obj:
            user_obj = User(membership_id=membership_id, membership_type=membership_type)
            session.add(user_obj)
            session.flush()
        return user_obj

    def _get_or_create_vault(self, session, user_id: int) -> Vault:
        vault_obj = session.query(Vault).filter_by(user_id=user_id).first()
        if not vault_obj:
            vault_obj = Vault(user_id=user_id)
            session.add(vault_obj)
            session.flush()
        return vault_obj

    def _persist_item_record(
        self,
        session,
        item_model,
        *,
        character_id: int | None = None,
        vault_id: int | None = None,
    ) -> Item:
        instance_id = self._safe_int(item_model.itemInstanceId)
        character_id = self._safe_int(character_id)
        vault_id = self._safe_int(vault_id)

        item_hash = self._safe_int(item_model.itemHash)
        if item_hash is None:
            item_hash = item_model.itemHash

        item_obj = None
        if instance_id is not None:
            item_obj = session.query(Item).filter_by(item_instance_id=instance_id).first()

        if not item_obj:
            filter_kwargs = {"item_hash": item_hash}
            if character_id is not None:
                filter_kwargs["character_id"] = character_id
            if vault_id is not None:
                filter_kwargs["vault_id"] = vault_id
            item_obj = session.query(Item).filter_by(**filter_kwargs).first()

        if not item_obj:
            item_obj = Item()

        # Compute new content hash from item model snapshot
        new_hash = None
        try:
            content_payload = {
                "itemHash": item_hash,
                "name": item_model.itemName,
                "type": item_model.itemType,
                "tier": item_model.itemTier,
                "powerValue": item_model.stats.get("Power"),
                "isEquipped": item_model.isEquipped,
                "stats": item_model.stats,
                "perks": item_model.perks,
                "statDetails": [detail.model_dump() for detail in item_model.statDetails],
            }
            new_hash = compute_hash(json.dumps(content_payload, sort_keys=True, default=str))
        except Exception:  # pragma: no cover - hashing best effort
            new_hash = None

        item_obj.character_id = character_id
        item_obj.vault_id = vault_id
        item_obj.item_hash = item_hash
        item_obj.item_instance_id = instance_id
        item_obj.name = item_model.itemName
        item_obj.type = item_model.itemType
        item_obj.tier = item_model.itemTier
        item_obj.power_value = item_model.stats.get("Power")
        item_obj.is_equipped = item_model.isEquipped

        old_hash = item_obj.content_hash
        if new_hash is not None:
            item_obj.content_hash = new_hash

        session.add(item_obj)
        session.flush()
        needs_refresh = (new_hash is None) or (old_hash != new_hash)
        if needs_refresh:
            self._sync_item_children(session, item_obj, item_model, instance_id)
        return item_obj

    def _delete_item(self, session, item_obj: Item) -> None:
        item_id = item_obj.item_id
        instance_id = item_obj.item_instance_id
        session.query(ItemStat).filter_by(item_id=item_id).delete(synchronize_session=False)
        session.query(ItemSocket).filter_by(item_id=item_id).delete(synchronize_session=False)
        session.query(ItemPlug).filter_by(item_id=item_id).delete(synchronize_session=False)
        if instance_id is not None:
            session.query(ItemEnergy).filter_by(instance_id=instance_id).delete(synchronize_session=False)
            session.query(ItemSocketChoice).filter_by(instance_id=instance_id).delete(synchronize_session=False)
            session.query(ItemSandboxPerk).filter_by(instance_id=instance_id).delete(synchronize_session=False)
        session.delete(item_obj)

    def _sync_item_children(self, session, item_obj: Item, item_model, instance_id: int | None) -> None:
        """Replace child records (stats, sockets, energy, etc.) for an item."""
        session.query(ItemStat).filter(ItemStat.item_id == item_obj.item_id).delete(synchronize_session=False)
        if item_model.statDetails:
            for detail in item_model.statDetails:
                stat_hash = self._safe_int(detail.hash)
                if stat_hash is None:
                    continue
                session.add(ItemStat(
                    item_id=item_obj.item_id,
                    stat_hash=stat_hash,
                    stat_name=detail.name,
                    stat_value=detail.value
                ))
        else:
            for stat_name, stat_value in item_model.stats.items():
                session.add(ItemStat(
                    item_id=item_obj.item_id,
                    stat_hash=0,
                    stat_name=stat_name,
                    stat_value=stat_value
                ))

        session.query(ItemPlug).filter(ItemPlug.item_id == item_obj.item_id).delete(synchronize_session=False)
        session.query(ItemSocket).filter(ItemSocket.item_id == item_obj.item_id).delete(synchronize_session=False)
        sockets = item_model.perks.get("sockets", []) or []
        for socket in sockets:
            socket_index = self._safe_int(socket.get("socketIndex"))
            if socket_index is None:
                continue
            socket_record = ItemSocket(
                item_id=item_obj.item_id,
                socket_index=socket_index,
                socket_type_hash=self._safe_int(socket.get("socketTypeHash")),
                category_name=socket.get("categoryName"),
                is_visible=bool(socket.get("isVisible", False)),
                is_enabled=bool(socket.get("isEnabled", False))
            )
            session.add(socket_record)
            equipped = socket.get("equipped") or {}
            plug_hash = self._safe_int(equipped.get("hash"))
            if plug_hash is not None:
                session.add(ItemPlug(
                    item_id=item_obj.item_id,
                    socket_index=socket_index,
                    plug_hash=plug_hash,
                    plug_name=equipped.get("name"),
                    plug_icon=equipped.get("icon"),
                    is_equipped=True
                ))

        if instance_id is not None:
            session.query(ItemEnergy).filter_by(instance_id=instance_id).delete(synchronize_session=False)
            energy_entries = item_model.perks.get("energy") or []
            if energy_entries:
                energy = energy_entries[0]
                session.add(ItemEnergy(
                    instance_id=instance_id,
                    energy_type_hash=self._safe_int(energy.get("type_hash")),
                    energy_type_name=energy.get("type_name"),
                    capacity=self._safe_int(energy.get("capacity")),
                    used=self._safe_int(energy.get("used")),
                    unused=self._safe_int(energy.get("unused"))
                ))

            session.query(ItemSocketChoice).filter_by(instance_id=instance_id).delete(synchronize_session=False)
            seen_choices: set[tuple[int, int]] = set()
            for choice in item_model.perks.get("reusablePlugs", []) or []:
                socket_index = self._safe_int(choice.get("socketIndex"))
                if socket_index is None:
                    continue
                for plug in choice.get("choices", []) or []:
                    plug_hash = self._safe_int(plug.get("hash"))
                    if plug_hash is None:
                        continue
                    key = (socket_index, plug_hash)
                    if key in seen_choices:
                        continue
                    seen_choices.add(key)
                    session.add(ItemSocketChoice(
                        instance_id=instance_id,
                        socket_index=socket_index,
                        plug_hash=plug_hash,
                        plug_name=plug.get("name")
                    ))

            session.query(ItemSandboxPerk).filter_by(instance_id=instance_id).delete(synchronize_session=False)
            perk_records: dict[int, dict] = {}
            for perk in item_model.perks.get("sandboxPerks", []) or []:
                perk_hash = self._safe_int(perk.get("hash"))
                if perk_hash is None:
                    continue
                current = perk_records.get(perk_hash)
                candidate = {
                    "name": perk.get("name"),
                    "icon": perk.get("icon"),
                    "is_active": bool(perk.get("active", False)),
                    "is_visible": bool(perk.get("visible", False)),
                }
                if current:
                    # Prefer records that are active; if active state matches, keep visible ones
                    if current["is_active"] and not candidate["is_active"]:
                        continue
                    if current["is_active"] == candidate["is_active"] and current["is_visible"]:
                        continue
                perk_records[perk_hash] = candidate

            for perk_hash, data in perk_records.items():
                session.add(ItemSandboxPerk(
                    instance_id=instance_id,
                    sandbox_perk_hash=perk_hash,
                    name=data["name"],
                    icon=data["icon"],
                    is_active=data["is_active"],
                    is_visible=data["is_visible"],
                ))

    def persist_vault(self, vault_model, membership_id, membership_type):
        """
        Persist a VaultModel to the database using ORM models.
        Args:
            vault_model: VaultModel instance
            membership_id: Destiny 2 membership ID
            membership_type: Destiny 2 membership type
        Returns:
            dict: Result status
        """
        try:
            session = self._get_session_with_cold_start_handling()
        except RuntimeError as e:
            logging.error("Failed to get database session: %s", e)
            return {"status": "error", "error": str(e)}
            
        try:
            user_obj = self._get_or_create_user(session, membership_id, membership_type)
            vault_obj = self._get_or_create_vault(session, user_obj.user_id)
            seen_item_ids: set[int] = set()
            for item in vault_model.items:
                db_item = self._persist_item_record(session, item, vault_id=vault_obj.vault_id)
                if db_item.item_id is not None:
                    seen_item_ids.add(db_item.item_id)

            existing_items = session.query(Item).filter_by(vault_id=vault_obj.vault_id).all()
            for db_item in existing_items:
                if db_item.item_id not in seen_item_ids:
                    self._delete_item(session, db_item)
            session.commit()
            return {"status": "success"}
        except Exception as e:
            session.rollback()
            logging.error("Failed to persist vault: %s", e)
            return {"status": "error", "error": str(e)}
        finally:
            session.close()

    def persist_characters(self, character_models, membership_id, membership_type):
        """
        Persist a list of CharacterModel instances to the database using ORM models.
        Args:
            character_models: List of CharacterModel instances
            membership_id: Destiny 2 membership ID
            membership_type: Destiny 2 membership type
        Returns:
            dict: Result status
        """
        try:
            session = self._get_session_with_cold_start_handling()
        except RuntimeError as e:
            logging.error("Failed to get database session: %s", e)
            return {"status": "error", "error": str(e)}
            
        try:
            user_obj = self._get_or_create_user(session, membership_id, membership_type)
            for char_model in character_models:
                character_id = self._safe_int(char_model.charId)
                if character_id is None:
                    logging.warning("Skipping character with non-numeric ID: %s", char_model.charId)
                    continue
                char_obj = session.query(Character).filter_by(character_id=character_id).first()
                if not char_obj:
                    char_obj = Character(character_id=character_id, user_id=user_obj.user_id)
                char_obj.user_id = user_obj.user_id
                char_obj.class_type = char_model.classType
                char_obj.light = self._safe_int(char_model.light)
                race_hash = None
                if char_model.race:
                    race_hash = race_name_to_hash().get(char_model.race)
                if race_hash is None:
                    race_hash = self._safe_int(char_model.race)
                char_obj.race_hash = race_hash
                session.add(char_obj)
                session.flush()

                seen_item_ids: set[int] = set()
                for item in char_model.items:
                    db_item = self._persist_item_record(session, item, character_id=char_obj.character_id)
                    if db_item.item_id is not None:
                        seen_item_ids.add(db_item.item_id)

                existing_items = session.query(Item).filter_by(character_id=char_obj.character_id).all()
                for db_item in existing_items:
                    if db_item.item_id not in seen_item_ids:
                        self._delete_item(session, db_item)
            session.commit()
            return {"status": "success"}
        except Exception as e:
            session.rollback()
            logging.error("Failed to persist characters: %s", e)
            return {"status": "error", "error": str(e)}
        finally:
            session.close()

    def persist_item(self, item_model, character_id=None, vault_id=None):
        """
        Persist a single ItemModel to the database using ORM models.
        Args:
            item_model: ItemModel instance
            character_id: Optional character_id to associate
            vault_id: Optional vault_id to associate
        Returns:
            dict: Result status
        """
        try:
            session = self._get_session_with_cold_start_handling()
        except RuntimeError as e:
            logging.error("Failed to get database session: %s", e)
            return {"status": "error", "error": str(e)}
            
        try:
            self._persist_item_record(session, item_model, character_id=character_id, vault_id=vault_id)
            session.commit()
            return {"status": "success"}
        except Exception as e:
            session.rollback()
            logging.error("Failed to persist item: %s", e)
            return {"status": "error", "error": str(e)}
        finally:
            session.close()

# Usage Example (for local testing only)
if __name__ == "__main__":
    agent = VaultSentinelDBAgent.instance()
    sample_query = {
        "intent": "list_items_by_stat",
        "filters": {
            "statThreshold": {"gte": 65, "stat": "Discipline"},
            "type": "armor",
            "location": ["vault"],
            "classType": "Warlock"
        },
        "output": {
            "includePerks": True,
            "includeStats": True,
            "includeInstanceData": True
        },
        "sort": {"field": "statValue", "direction": "desc"},
        "limit": 25
    }
    try:
        result = agent.process_query(sample_query)
        print(result)
    except Exception as exc:
        logging.error("Error processing query: %s", exc)
