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
import threading
import time
import urllib.parse
from typing import Any, Dict

from openai import AzureOpenAI
from sqlalchemy import create_engine, orm, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.exc import TimeoutError as SaTimeoutError
import re

from constants import (
    OPENAI_API_KEY, OPENAI_API_VERSION, OPENAI_DEPLOYMENT,
    OPENAI_ENDPOINT, SQL_DATABASE, SQL_DRIVER, SQL_SERVER,
    SQL_USER, SQL_PASSWORD
)
from models import Character, Item, ItemStat, User, Vault


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
        if SQL_USER and SQL_PASSWORD:
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
            )
            sqlalchemy_url = "mssql+pyodbc:///?odbc_connect=" + urllib.parse.quote_plus(odbc_str)
            logging.info("Using Managed Identity for database connection.")

        # Engine configuration optimized for Azure SQL cold starts
        engine_config = {
            "pool_pre_ping": True,      # Validate connections before use
            "pool_recycle": 1800,       # Recycle connections every 30 minutes
            "pool_timeout": 60,         # Extended pool timeout for cold starts
            "max_overflow": 5,          # Conservative overflow for serverless
            "pool_size": 2,             # Small pool size for serverless
            "echo": False,              # Set to True for SQL debugging
            "connect_args": {
                "timeout": 60,          # Connection timeout
                "autocommit": False     # Explicit transaction control
            }
        }

        try:
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
                is_cold_start = any(indicator in error_msg for indicator in [
                    'login timeout', 'connection timeout', 'hyt00', 
                    'server is not ready', 'database is starting'
                ])
                
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
            user_obj = session.query(User).filter_by(membership_id=membership_id).first()
            if not user_obj:
                user_obj = User(membership_id=membership_id, membership_type=membership_type)
                session.add(user_obj)
                session.flush()
            vault_obj = Vault(user_id=user_obj.user_id)
            session.add(vault_obj)
            session.flush()
            for item in vault_model.items:
                item_obj = Item(
                    vault_id=vault_obj.vault_id,
                    item_hash=item.itemHash,
                    item_instance_id=item.itemInstanceId,
                    name=item.itemName,
                    type=item.itemType,
                    tier=item.itemTier,
                    power_value=item.stats.get("Power"),
                    is_equipped=item.isEquipped
                )
                session.add(item_obj)
                session.flush()
                for stat_name, stat_value in item.stats.items():
                    stat_obj = ItemStat(
                        item_id=item_obj.item_id,
                        stat_hash=0,
                        stat_name=stat_name,
                        stat_value=stat_value
                    )
                    session.add(stat_obj)
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
            user_obj = session.query(User).filter_by(membership_id=membership_id).first()
            if not user_obj:
                user_obj = User(membership_id=membership_id, membership_type=membership_type)
                session.add(user_obj)
                session.flush()
            for char_model in character_models:
                char_obj = Character(
                    user_id=user_obj.user_id,
                    character_id=char_model.charId,
                    class_type=char_model.classType,
                    light=char_model.light,
                    race_hash=0
                )
                session.add(char_obj)
                session.flush()
                for item in char_model.items:
                    item_obj = Item(
                        character_id=char_obj.character_id,
                        item_hash=item.itemHash,
                        item_instance_id=item.itemInstanceId,
                        name=item.itemName,
                        type=item.itemType,
                        tier=item.itemTier,
                        power_value=item.stats.get("Power"),
                        is_equipped=item.isEquipped
                    )
                    session.add(item_obj)
                    session.flush()
                    for stat_name, stat_value in item.stats.items():
                        stat_obj = ItemStat(
                            item_id=item_obj.item_id,
                            stat_hash=0,
                            stat_name=stat_name,
                            stat_value=stat_value
                        )
                        session.add(stat_obj)
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
            item_obj = Item(
                character_id=character_id,
                vault_id=vault_id,
                item_hash=item_model.itemHash,
                item_instance_id=item_model.itemInstanceId,
                name=item_model.itemName,
                type=item_model.itemType,
                tier=item_model.itemTier,
                power_value=item_model.stats.get("Power"),
                is_equipped=item_model.isEquipped
            )
            session.add(item_obj)
            session.flush()
            for stat_name, stat_value in item_model.stats.items():
                stat_obj = ItemStat(
                    item_id=item_obj.item_id,
                    stat_hash=0,
                    stat_name=stat_name,
                    stat_value=stat_value
                )
                session.add(stat_obj)
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
