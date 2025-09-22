
import pyodbc
import os
import json

# Load environment variables from local.settings.json if present
settings_path = os.path.join(os.path.dirname(__file__), "local.settings.json")
if os.path.exists(settings_path):
    with open(settings_path, "r") as f:
        settings = json.load(f)
        for k, v in settings.get("Values", {}).items():
            os.environ.setdefault(k, v)

server = os.getenv("AZURE_SQL_SERVER")
database = os.getenv("AZURE_SQL_DATABASE")
username = os.getenv("AZURE_SQL_ADMIN_LOGIN")
password = os.getenv("AZURE_SQL_ADMIN_PASSWORD")
driver = os.getenv("AZURE_SQL_DRIVER", "ODBC Driver 18 for SQL Server")

conn_str = (
    f"DRIVER={{{driver}}};"
    f"SERVER={server};"
    f"DATABASE={database};"
    f"UID={username};"
    f"PWD={password};"
    "Encrypt=yes;"
    "TrustServerCertificate=no;"
    "Connection Timeout=30;"
)

print("Attempting connection with:")
print(f"SERVER={server}")
print(f"DATABASE={database}")
print(f"UID={username}")

try:
    with pyodbc.connect(conn_str) as conn:
        print("Connection successful!")
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        print("Test query result:", cursor.fetchone())
except Exception as e:
    print("Connection failed:", e)
