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
import os
from typing import Any, Dict

from sqlalchemy import create_engine, orm
from azure.identity import DefaultAzureCredential
from openai import AzureOpenAI

from models import Character, User, Vault, Item, ItemStat

# Azure OpenAI and SQL DB configuration
OPENAI_ENDPOINT = os.getenv("AZURE_OPENAI_ENDPOINT")
OPENAI_DEPLOYMENT = os.getenv("AZURE_OPENAI_DEPLOYMENT")
OPENAI_API_VERSION = os.getenv("AZURE_OPENAI_API_VERSION", "2023-05-15")
OPENAI_API_KEY = os.getenv("AZURE_OPENAI_API_KEY")
SQL_SERVER = os.getenv("AZURE_SQL_SERVER")
SQL_DATABASE = os.getenv("AZURE_SQL_DATABASE")
SQL_DRIVER = os.getenv("AZURE_SQL_DRIVER", "ODBC Driver 18 for SQL Server")

class VaultSentinelDBAgent:
    """
    Business logic agent for Destiny 2 gear queries, designed for use in Azure Function App endpoints.
    Implements schema validation and core query processing logic.
    """

    def __init__(self):
        logging.info("VaultSentinelDBAgent initialized.")
        # Managed Identity for Azure services
        self.credential = DefaultAzureCredential()
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
        # Build connection string from environment variables
        if SQL_SERVER and SQL_DATABASE and SQL_DRIVER:
            # SQLAlchemy ODBC connection string for MSSQL
            connection_string = (
                f"mssql+pyodbc://@{SQL_SERVER}/{SQL_DATABASE}?"
                f"driver={SQL_DRIVER.replace(' ', '+')}"
                "&authentication=ActiveDirectoryMsi"
                "&Encrypt=yes&TrustServerCertificate=no"
            )
            try:
                self.engine = create_engine(connection_string)
                self.Session = orm.sessionmaker(bind=self.engine)
                logging.info("SQLAlchemy engine/session initialized for Azure SQL DB.")
            except Exception as e:
                logging.error("Failed to initialize SQLAlchemy engine: %s", e)
                self.engine = None
                self.Session = None
        else:
            logging.error("SQL_SERVER, SQL_DATABASE, or SQL_DRIVER environment variable not set.")
            self.Session = None


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
            if not sql_query.lower().startswith("select"):
                logging.error("AI did not return a SELECT query.")
                return {"status": "error", "error": "AI did not return a SELECT query."}

            session = self.Session()
            query_result = session.execute(sql_query)
            rows = query_result.fetchall()
            columns = query_result.keys()
            data = [dict(zip(columns, row)) for row in rows]
            return {"status": "success", "data": data, "sql": sql_query}
        except Exception as e:
            logging.error("process_query failed: %s", e)
            return {"status": "error", "error": str(e)}

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
        if not self.Session:
            logging.error("SQLAlchemy sessionmaker not initialized.")
            return {"status": "error", "error": "Sessionmaker not initialized"}
        session = self.Session()
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
        if not self.Session:
            logging.error("SQLAlchemy sessionmaker not initialized.")
            return {"status": "error", "error": "Sessionmaker not initialized"}
        session = self.Session()
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
        if not self.Session:
            logging.error("SQLAlchemy sessionmaker not initialized.")
            return {"status": "error", "error": "Sessionmaker not initialized"}
        session = self.Session()
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
    agent = VaultSentinelDBAgent()
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
