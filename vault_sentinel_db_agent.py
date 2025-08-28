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

import pyodbc
from azure.identity import DefaultAzureCredential
from openai import AzureOpenAI

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
        # Azure SQL DB connection
        self.sql_conn = None
        if SQL_SERVER and SQL_DATABASE:
            conn_str = (
                f"Driver={{{SQL_DRIVER}}};Server={SQL_SERVER};Database={SQL_DATABASE};"
                "Authentication=ActiveDirectoryMsi;Encrypt=yes;TrustServerCertificate=no;"
            )
            try:
                self.sql_conn = pyodbc.connect(conn_str)
                logging.info("Connected to Azure SQL DB.")
            except Exception as e:
                logging.error("Failed to connect to Azure SQL DB: %s", e)

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
        This method is wired to Azure OpenAI and Azure SQL DB.
        """
        if not self.validate_query(query):
            raise ValueError("Query does not conform to schema.")
        logging.info("Processing query: %s", query["intent"])

        with open("db-agent-instructions.md", "r", encoding="utf-8") as f:
            instructions = f.read()

        system_message = {
            "role": "system",
            "content": instructions
        }

        user_message = {
            "role": "user",
            "content": json.dumps(query, indent=2)  # Ensure query is formatted as JSON
        }

        try:
            response = self.chat_client.chat.completions.create(
                messages=[system_message, user_message],
                temperature=0.0,  # Adjust temperature for response variability
                frequency_penalty=0.0,  # No penalty for repeated tokens
                presence_penalty=-2.0  # Max penalty for new topics
            )
            
            chat_content = response.choices[0].message.content if response.choices else ""
            return {"status": "success", "data": chat_content}
        except Exception as e:
            logging.error("Chat completion client failed: %s", e)
            return {"status": "error", "error": str(e)}


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
