#pylint: disable=invalid-name, line-too-long, c-extension-no-member
"""
Vault Sentinel DB Agent for Azure AI
------------------------------------
This module implements a secure, schema-compliant agent that processes Destiny 2 gear queries using Azure AI.
All queries must conform to the embedded schema. The agent uses Managed Identity for authentication and adheres
to Azure best practices for reliability, security, and performance.
"""


import json
import logging
import re
import threading
import time
import urllib.parse
from typing import Any, Dict, cast

import pyodbc

from openai import AzureOpenAI
from openai import (
    APIError,
    APIConnectionError,
    APITimeoutError,
    RateLimitError,
    BadRequestError,
)
from sqlalchemy import create_engine, orm, text
from sqlalchemy.exc import OperationalError, SQLAlchemyError
from sqlalchemy.exc import TimeoutError as SaTimeoutError
from sqlalchemy.pool import NullPool

from VaultSentinelPlatform.common.helpers import compute_hash
from VaultSentinelPlatform.config import (
    OPENAI_API_KEY,
    OPENAI_API_VERSION,
    OPENAI_DEPLOYMENT,
    OPENAI_ENDPOINT,
    SQL_DATABASE,
    SQL_DISABLE_ODBC_POOLING,
    SQL_DRIVER,
    SQL_PASSWORD,
    SQL_SERVER,
    SQL_USER,
)
from VaultSentinelPlatform.exceptions import (
    BusinessRuleViolationError,
    DependencyUnavailableError,
    QueryValidationError,
)
from VaultSentinelPlatform.manifest.identity import race_name_to_hash
from VaultSentinelPlatform.models import (
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


class VaultSentinelDBAgent:
    """
    A business logic agent for processing Destiny 2 gear queries, designed for use in Azure Function App endpoints.

    This class implements schema validation, core query processing logic, and Azure SQL cold start mitigation.
    """

    _instance = None
    _DB_SESSION_ERROR_TEMPLATE = "Failed to get database session: %s"
    _COLD_START_INDICATORS = (
        "login timeout",
        "connection timeout",
        "hyt00",
        "server is not ready",
        "database is starting",
        "not currently available",
        "40613",
    )

    @classmethod
    def instance(cls) -> "VaultSentinelDBAgent":
        """
        Provides a thread-safe singleton instance of the DB agent.

        Returns:
            VaultSentinelDBAgent: The singleton instance of the DB agent.
        """
        if not hasattr(cls, "_instance_lock"):
            cls._instance_lock = threading.RLock()
        if cls._instance is None:
            with cls._instance_lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        """
        Resets the singleton instance. Useful for testing purposes.
        """
        if hasattr(cls, "_instance_lock"):
            with cls._instance_lock:
                cls._instance = None
        else:
            cls._instance = None

    @classmethod
    def is_db_configured(cls) -> bool:
        """
        Checks if the minimal database configuration constants are set.

        Returns:
            bool: True if the database is configured, False otherwise.
        """
        return bool(SQL_SERVER and SQL_DATABASE and SQL_DRIVER)

    def __init__(self):
        """
        Initializes the VaultSentinelDBAgent, setting up Azure OpenAI and SQLAlchemy configurations.
        """
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
        self.session_factory = None
        self._connection_warmed = False
        self._initialize_database_connection()


    def _initialize_database_connection(self):
        """
        Initializes the database connection optimized for Azure SQL Database cold starts.
        """
        if not (SQL_SERVER and SQL_DATABASE and SQL_DRIVER):
            logging.error("SQL_SERVER, SQL_DATABASE, or SQL_DRIVER constant not set.")
            return

        # Choose authentication method: SQL auth if user/password, else Managed Identity
        pooling_segment = "Pooling=no;" if SQL_DISABLE_ODBC_POOLING else ""
        if SQL_DISABLE_ODBC_POOLING:
            try:
                pyodbc.pooling = False
            except AttributeError as exc:  # pragma: no cover - defensive
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
            self.session_factory = orm.sessionmaker(bind=self.engine)
            logging.info("SQLAlchemy engine/session initialized for Azure SQL DB.")
            # Attempt connection warmup in background
            self._warmup_connection()
        except (SQLAlchemyError, pyodbc.Error) as e:
            logging.error("Failed to initialize SQLAlchemy engine: %s", e)
            self.engine = None
            self.session_factory = None

    @staticmethod
    def _close_session_quietly(session) -> None:
        """Close a SQLAlchemy session if one was created."""
        if session is not None:
            session.close()

    @classmethod
    def _is_cold_start_error(cls, error: Exception) -> bool:
        """Return True when a database exception matches known Azure SQL cold-start patterns."""
        error_msg = str(error).lower()
        return any(indicator in error_msg for indicator in cls._COLD_START_INDICATORS)

    def _open_validated_session(self):
        """Create a session and verify the connection with a lightweight query."""
        if not self.session_factory:
            raise DependencyUnavailableError(
                "Database session not available",
                details={"dependency": "database_session_factory"},
            )
        session = self.session_factory()
        session.execute(text("SELECT 1")).scalar()
        return session

    def _warmup_connection(self):
        """Warm up the database connection to mitigate Azure SQL cold starts."""
        if not self.session_factory:
            return

        max_warmup_attempts = 3
        warmup_delay = 2

        for attempt in range(max_warmup_attempts):
            session = None
            try:
                session = self._open_validated_session()
                self._connection_warmed = True
                logging.info("Database connection warmed up successfully.")
                return
            except (OperationalError, SaTimeoutError) as e:
                logging.warning(
                    "Database warmup attempt %d/%d failed (expected for cold start): %s",
                    attempt + 1,
                    max_warmup_attempts,
                    str(e),
                )
                if attempt < max_warmup_attempts - 1:
                    time.sleep(warmup_delay)
                    warmup_delay *= 2
            except (SQLAlchemyError, pyodbc.Error) as e:
                logging.error("Unexpected database error during warmup: %s", e)
                break
            finally:
                self._close_session_quietly(session)

        logging.warning("Database warmup incomplete - connection may experience cold start delays.")

    def _get_session_with_cold_start_handling(self):
        """
        Retrieve a database session with Azure SQL cold start mitigation.

        Returns:
            sqlalchemy.orm.Session: A SQLAlchemy session object.

        Raises:
            DependencyUnavailableError: If the session dependency is not initialized
                or the database session cannot be created after retry attempts.
        """
        if not self.session_factory:
            raise DependencyUnavailableError(
                "Database session not available",
                details={"dependency": "database_session_factory"},
            )

        max_attempts = 5 if not self._connection_warmed else 3
        base_delay = 2

        for attempt in range(max_attempts):
            try:
                return self._open_validated_session()
            except (OperationalError, SaTimeoutError) as e:
                if self._is_cold_start_error(e) and attempt < max_attempts - 1:
                    delay = base_delay * (2 ** attempt)
                    logging.warning(
                        "Cold start detected on attempt %d/%d, retrying in %d seconds: %s",
                        attempt + 1,
                        max_attempts,
                        delay,
                        str(e),
                    )
                    time.sleep(delay)
                    continue
                raise DependencyUnavailableError(
                    "Database session is temporarily unavailable after retry attempts.",
                    details={
                        "dependency": "database_session",
                        "attempts": attempt + 1,
                        "cold_start": self._is_cold_start_error(e),
                    },
                ) from e
            except (SQLAlchemyError, pyodbc.Error) as e:
                raise DependencyUnavailableError(
                    "Database session is unavailable due to a database error.",
                    details={
                        "dependency": "database_session",
                        "attempts": attempt + 1,
                    },
                ) from e

        raise DependencyUnavailableError(
            "Database session is unavailable after retry attempts.",
            details={"dependency": "database_session", "attempts": max_attempts},
        )

    def validate_query(self, query: Dict[str, Any]) -> bool:
        """
        Validates a query against the embedded schema, ensuring all required keys are present and valid.

        Args:
            query (Dict[str, Any]): The query to validate.

        Returns:
            bool: True if the query is valid, False otherwise.
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
            raise QueryValidationError(
                "Query does not conform to schema.",
                details={"provided_keys": sorted(query.keys())},
            )
        logging.info("Processing query: %s", query["intent"])

        if not self.session_factory:
            logging.error("SQLAlchemy sessionmaker not initialized.")
            return {"status": "error", "error": "Sessionmaker not initialized"}

        if self.chat_client is None:
            logging.error("Azure OpenAI client is not configured. Set AZURE_OPENAI_* settings.")
            return {"status": "error", "error": "Azure OpenAI not configured."}

        deployment_name = OPENAI_DEPLOYMENT or ""

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
        messages = cast(Any, [system_message, user_message])

        try:
            response = self.chat_client.chat.completions.create(
                model=deployment_name,
                messages=messages,
                temperature=0.0,
                frequency_penalty=0.0,
                presence_penalty=-2.0
            )
            response_content = response.choices[0].message.content if response.choices else ""
            sql_query = response_content.strip() if isinstance(response_content, str) else ""
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

        except BadRequestError as e:
            logging.error("Azure OpenAI bad request: %s", e)
            return {"status": "error", "error": "Azure OpenAI bad request. Check prompt/schema and inputs."}
        except RateLimitError as e:
            logging.warning("Azure OpenAI rate limit: %s", e)
            return {"status": "error", "error": "Azure OpenAI rate limit exceeded. Please retry shortly."}
        except (APIConnectionError, APITimeoutError) as e:
            logging.error("Azure OpenAI network/timeout error: %s", e)
            return {"status": "error", "error": "Azure OpenAI network or timeout error. Please try again."}
        except APIError as e:
            logging.error("Azure OpenAI service error: %s", e)
            return {"status": "error", "error": "Azure OpenAI service error. Try again later."}
        except DependencyUnavailableError as e:
            logging.error("process_query dependency error: %s", e)
            return {"status": "error", "error": str(e)}
        except (SQLAlchemyError, pyodbc.Error, ValueError) as e:
            logging.error("process_query DB/validation error: %s", e)
            return {"status": "error", "error": str(e)}
        # Let unexpected errors (e.g., OpenAI SDK) propagate to the caller

    # --- SQL Validation ---
    _ALLOWED_TABLES = {
        'users', 'vaults', 'characters', 'items', 'itemstats', 'itemsockets',
        'itemplugs', 'itemsocketchoices', 'itemsandboxperks', 'itemenergy', 'itemsocketlayout'
    }

    _FORBIDDEN_KEYWORDS = {
        'insert', 'update', 'delete', 'drop', 'alter', 'create', 'exec', 'execute',
        'merge', 'grant', 'revoke', 'truncate', 'sp_', 'xp_'
    }

    @staticmethod
    def _normalize_table_name(name: str) -> str:
        """Normalize SQL table identifiers like `dbo.[Items]` to `items`."""
        normalized = name.strip().strip("[]")
        if "." in normalized:
            normalized = normalized.split(".")[-1]
        return normalized.lower()

    def _find_forbidden_keyword(self, query_lower: str) -> str | None:
        """Return the first forbidden SQL keyword found in the query, if any."""
        for keyword in self._FORBIDDEN_KEYWORDS:
            if re.search(rf"\b{re.escape(keyword)}\b", query_lower):
                return keyword
        return None

    def _iter_referenced_tables(self, query_lower: str) -> list[str]:
        """Extract normalized table names referenced after `FROM` and `JOIN`."""
        matches = re.findall(r"\bfrom\s+([\w\[\]\.]+)|\bjoin\s+([\w\[\]\.]+)", query_lower)
        return [
            self._normalize_table_name(token[0] or token[1])
            for token in matches
            if token[0] or token[1]
        ]

    def _validate_sql(self, sql_query: str) -> tuple[bool, str]:
        """Validate that AI-generated SQL is a single safe `SELECT` over allowed tables."""
        query_text = (sql_query or "").strip()
        if not query_text:
            return False, "empty query"

        query_lower = query_text.lower()
        if not query_lower.startswith("select"):
            return False, "must be a SELECT query"
        if len(query_text) > 8000:
            return False, "query too long"
        if ";" in query_lower:
            return False, "multiple statements not allowed"
        if "--" in query_lower or "/*" in query_lower or "*/" in query_lower:
            return False, "comments not allowed"

        forbidden_keyword = self._find_forbidden_keyword(query_lower)
        if forbidden_keyword:
            return False, f"forbidden keyword: {forbidden_keyword}"

        for table_name in self._iter_referenced_tables(query_lower):
            if table_name not in self._ALLOWED_TABLES:
                return False, f"unknown or disallowed table: {table_name}"
        return True, "ok"

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

    def _require_int(self, value: Any, label: str) -> int:
        """Convert an identifier to `int` and fail fast if it is unavailable."""
        normalized = self._safe_int(value)
        if normalized is None:
            raise BusinessRuleViolationError(
                f"Expected {label} to be populated",
                details={"label": label},
            )
        return normalized

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
        except (TypeError, ValueError):  # pragma: no cover - hashing best effort
            new_hash = None

        item_record = cast(Any, item_obj)
        item_record.character_id = character_id
        item_record.vault_id = vault_id
        item_record.item_hash = item_hash
        item_record.item_instance_id = instance_id
        item_record.name = item_model.itemName
        item_record.type = item_model.itemType
        item_record.tier = item_model.itemTier
        item_record.power_value = item_model.stats.get("Power")
        item_record.is_equipped = item_model.isEquipped

        old_hash = cast(str | None, getattr(item_obj, "content_hash", None))
        if new_hash is not None:
            item_record.content_hash = new_hash

        session.add(item_obj)
        session.flush()
        needs_refresh = new_hash is None or old_hash != new_hash
        if needs_refresh:
            self._sync_item_children(session, item_obj, item_model, instance_id)
        return item_obj

    def _delete_item(self, session, item_obj: Item) -> None:
        item_id = self._require_int(getattr(item_obj, "item_id", None), "item.item_id")
        instance_id = self._safe_int(getattr(item_obj, "item_instance_id", None))
        session.query(ItemStat).filter_by(item_id=item_id).delete(synchronize_session=False)
        session.query(ItemPlug).filter_by(item_id=item_id).delete(synchronize_session=False)
        session.query(ItemSocket).filter_by(item_id=item_id).delete(synchronize_session=False)
        if instance_id is not None:
            session.query(ItemEnergy).filter_by(instance_id=instance_id).delete(synchronize_session=False)
            session.query(ItemSocketChoice).filter_by(instance_id=instance_id).delete(synchronize_session=False)
            session.query(ItemSandboxPerk).filter_by(instance_id=instance_id).delete(synchronize_session=False)
        session.delete(item_obj)

    def _sync_item_stats(self, session, item_id: int, item_model) -> None:
        """Replace the stat rows for an item."""
        session.query(ItemStat).filter(ItemStat.item_id == item_id).delete(synchronize_session=False)
        if item_model.statDetails:
            for detail in item_model.statDetails:
                stat_hash = self._safe_int(detail.hash)
                if stat_hash is None:
                    continue
                session.add(ItemStat(
                    item_id=item_id,
                    stat_hash=stat_hash,
                    stat_name=detail.name,
                    stat_value=detail.value,
                ))
            return

        for stat_name, stat_value in item_model.stats.items():
            session.add(ItemStat(
                item_id=item_id,
                stat_hash=0,
                stat_name=stat_name,
                stat_value=stat_value,
            ))

    def _sync_item_sockets(self, session, item_id: int, item_model) -> None:
        """Replace the socket and equipped plug rows for an item."""
        session.query(ItemPlug).filter(ItemPlug.item_id == item_id).delete(synchronize_session=False)
        session.query(ItemSocket).filter(ItemSocket.item_id == item_id).delete(synchronize_session=False)
        for socket in item_model.perks.get("sockets", []) or []:
            socket_index = self._safe_int(socket.get("socketIndex"))
            if socket_index is None:
                continue
            session.add(ItemSocket(
                item_id=item_id,
                socket_index=socket_index,
                socket_type_hash=self._safe_int(socket.get("socketTypeHash")),
                category_name=socket.get("categoryName"),
                is_visible=bool(socket.get("isVisible", False)),
                is_enabled=bool(socket.get("isEnabled", False)),
            ))
            equipped = socket.get("equipped") or {}
            plug_hash = self._safe_int(equipped.get("hash"))
            if plug_hash is not None:
                session.add(ItemPlug(
                    item_id=item_id,
                    socket_index=socket_index,
                    plug_hash=plug_hash,
                    plug_name=equipped.get("name"),
                    plug_icon=equipped.get("icon"),
                    is_equipped=True,
                ))

    @staticmethod
    def _select_preferred_perk(existing: dict | None, candidate: dict) -> dict:
        """Prefer active perk records, then visible ones, when deduplicating sandbox perks."""
        if existing is None:
            return candidate
        if existing["is_active"] and not candidate["is_active"]:
            return existing
        if existing["is_active"] == candidate["is_active"] and existing["is_visible"]:
            return existing
        return candidate

    def _build_perk_records(self, item_model) -> dict[int, dict]:
        """Deduplicate sandbox perk rows while preferring active and visible entries."""
        perk_records: dict[int, dict] = {}
        for perk in item_model.perks.get("sandboxPerks", []) or []:
            perk_hash = self._safe_int(perk.get("hash"))
            if perk_hash is None:
                continue
            candidate = {
                "name": perk.get("name"),
                "icon": perk.get("icon"),
                "is_active": bool(perk.get("active", False)),
                "is_visible": bool(perk.get("visible", False)),
            }
            perk_records[perk_hash] = self._select_preferred_perk(perk_records.get(perk_hash), candidate)
        return perk_records

    def _sync_item_energy(self, session, instance_id: int, item_model) -> None:
        """Replace the per-instance energy row for an item."""
        session.query(ItemEnergy).filter_by(instance_id=instance_id).delete(synchronize_session=False)
        energy_entries = item_model.perks.get("energy") or []
        if not energy_entries:
            return

        energy = energy_entries[0]
        session.add(ItemEnergy(
            instance_id=instance_id,
            energy_type_hash=self._safe_int(energy.get("type_hash")),
            energy_type_name=energy.get("type_name"),
            capacity=self._safe_int(energy.get("capacity")),
            used=self._safe_int(energy.get("used")),
            unused=self._safe_int(energy.get("unused")),
        ))

    def _sync_reusable_plug_choices(self, session, instance_id: int, item_model) -> None:
        """Replace reusable plug choice rows for an item instance."""
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
                    plug_name=plug.get("name"),
                ))

    def _sync_item_instance_children(self, session, instance_id: int, item_model) -> None:
        """Replace instance-specific child rows such as energy, reusable plugs, and sandbox perks."""
        self._sync_item_energy(session, instance_id, item_model)
        self._sync_reusable_plug_choices(session, instance_id, item_model)
        session.query(ItemSandboxPerk).filter_by(instance_id=instance_id).delete(synchronize_session=False)
        for perk_hash, data in self._build_perk_records(item_model).items():
            session.add(ItemSandboxPerk(
                instance_id=instance_id,
                sandbox_perk_hash=perk_hash,
                name=data["name"],
                icon=data["icon"],
                is_active=data["is_active"],
                is_visible=data["is_visible"],
            ))

    def _sync_item_children(self, session, item_obj: Item, item_model, instance_id: int | None) -> None:
        """Replace child records (stats, sockets, energy, etc.) for an item."""
        item_id = self._require_int(getattr(item_obj, "item_id", None), "item.item_id")
        self._sync_item_stats(session, item_id, item_model)
        self._sync_item_sockets(session, item_id, item_model)
        if instance_id is not None:
            self._sync_item_instance_children(session, instance_id, item_model)

    def _collect_persisted_item_ids(
        self,
        session,
        items,
        *,
        character_id: int | None = None,
        vault_id: int | None = None,
    ) -> set[int]:
        """Persist a sequence of items and return the set of resulting database item IDs."""
        seen_item_ids: set[int] = set()
        for item in items:
            db_item = self._persist_item_record(session, item, character_id=character_id, vault_id=vault_id)
            item_id = self._safe_int(getattr(db_item, "item_id", None))
            if item_id is not None:
                seen_item_ids.add(item_id)
        return seen_item_ids

    def _delete_missing_items(self, session, existing_items, seen_item_ids: set[int]) -> None:
        """Delete persisted items that were not present in the latest source payload."""
        for db_item in existing_items:
            item_id = self._safe_int(getattr(db_item, "item_id", None))
            if item_id is None or item_id not in seen_item_ids:
                self._delete_item(session, db_item)

    def _upsert_character(self, session, user_id: int, char_model) -> Character | None:
        """Create or update a character ORM record from a decoded character model."""
        character_id = self._safe_int(char_model.charId)
        if character_id is None:
            logging.warning("Skipping character with non-numeric ID: %s", char_model.charId)
            return None

        char_obj = session.query(Character).filter_by(character_id=character_id).first()
        if not char_obj:
            char_obj = Character(character_id=character_id, user_id=user_id)

        race_hash = race_name_to_hash().get(char_model.race) if char_model.race else None
        if race_hash is None:
            race_hash = self._safe_int(char_model.race)

        char_record = cast(Any, char_obj)
        char_record.user_id = user_id
        char_record.class_type = char_model.classType
        char_record.light = self._safe_int(char_model.light)
        char_record.race_hash = race_hash
        session.add(char_obj)
        session.flush()
        return char_obj

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
        except DependencyUnavailableError as e:
            logging.error(self._DB_SESSION_ERROR_TEMPLATE, e)
            return {"status": "error", "error": str(e)}

        try:
            user_obj = self._get_or_create_user(session, membership_id, membership_type)
            user_id = self._require_int(getattr(user_obj, "user_id", None), "user.user_id")
            vault_obj = self._get_or_create_vault(session, user_id)
            vault_id = self._require_int(getattr(vault_obj, "vault_id", None), "vault.vault_id")
            seen_item_ids = self._collect_persisted_item_ids(session, vault_model.items, vault_id=vault_id)
            existing_items = session.query(Item).filter_by(vault_id=vault_id).all()
            self._delete_missing_items(session, existing_items, seen_item_ids)
            session.commit()
            return {"status": "success"}
        except (SQLAlchemyError, pyodbc.Error) as e:
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
        except DependencyUnavailableError as e:
            logging.error(self._DB_SESSION_ERROR_TEMPLATE, e)
            return {"status": "error", "error": str(e)}

        try:
            user_obj = self._get_or_create_user(session, membership_id, membership_type)
            user_id = self._require_int(getattr(user_obj, "user_id", None), "user.user_id")
            for char_model in character_models:
                char_obj = self._upsert_character(session, user_id, char_model)
                if char_obj is None:
                    continue
                character_id = self._require_int(getattr(char_obj, "character_id", None), "character.character_id")
                seen_item_ids = self._collect_persisted_item_ids(
                    session,
                    char_model.items,
                    character_id=character_id,
                )
                existing_items = session.query(Item).filter_by(character_id=character_id).all()
                self._delete_missing_items(session, existing_items, seen_item_ids)
            session.commit()
            return {"status": "success"}
        except (SQLAlchemyError, pyodbc.Error) as e:
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
        except DependencyUnavailableError as e:
            logging.error(self._DB_SESSION_ERROR_TEMPLATE, e)
            return {"status": "error", "error": str(e)}

        try:
            self._persist_item_record(session, item_model, character_id=character_id, vault_id=vault_id)
            session.commit()
            return {"status": "success"}
        except (SQLAlchemyError, pyodbc.Error) as e:
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
    except (SQLAlchemyError, pyodbc.Error, ValueError) as exc:
        logging.error("Error processing query: %s", exc)
