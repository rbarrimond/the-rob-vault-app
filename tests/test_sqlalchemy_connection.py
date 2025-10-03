"""Quick connectivity check using SQLAlchemy with the Azure SQL settings."""

import json
import os
import urllib.parse

from sqlalchemy import create_engine, text
from sqlalchemy.pool import NullPool


def _load_local_settings():
    settings_path = os.path.join(os.path.dirname(__file__), "../local.settings.json")
    if os.path.exists(settings_path):
        with open(settings_path, "r", encoding="utf-8") as handle:
            settings = json.load(handle)
            for key, value in settings.get("Values", {}).items():
                os.environ.setdefault(key, value)


def main():
    _load_local_settings()

    server = os.getenv("AZURE_SQL_SERVER")
    database = os.getenv("AZURE_SQL_DATABASE")
    username = os.getenv("AZURE_SQL_ADMIN_LOGIN")
    password = os.getenv("AZURE_SQL_ADMIN_PASSWORD")
    driver = os.getenv("AZURE_SQL_DRIVER", "ODBC Driver 18 for SQL Server")
    disable_pooling = os.getenv("SQL_DISABLE_ODBC_POOLING", "false").lower() in {"1", "true", "yes"}

    # Disable pyodbc-level pooling before any connections are created when requested
    import pyodbc  # pylint: disable=import-outside-toplevel, import-outside-module
    if disable_pooling:
        pyodbc.pooling = False

    pooling_segment = "Pooling=no;" if disable_pooling else ""
    odbc_str = (
        f"DRIVER={{{driver}}};"
        f"SERVER={server};"
        f"DATABASE={database};"
        f"UID={username};"
        f"PWD={password};"
        "Encrypt=yes;"
        "TrustServerCertificate=no;"
        "Connection Timeout=30;"
        f"{pooling_segment}"
    )

    encoded_plus = urllib.parse.quote_plus(odbc_str)
    encoded = urllib.parse.quote(odbc_str)
    sqlalchemy_url_plus = "mssql+pyodbc:///?odbc_connect=" + encoded_plus
    sqlalchemy_url = "mssql+pyodbc:///?odbc_connect=" + encoded
    engine_kwargs: dict = {}
    if disable_pooling:
        engine_kwargs["poolclass"] = NullPool
    else:
        engine_kwargs.update({
            "pool_pre_ping": True,
            "pool_recycle": 1800,
            "pool_timeout": 60,
            "max_overflow": 5,
            "pool_size": 2,
        })

    connect_args = {
        "timeout": 60,
        "autocommit": False,
    }

    print("Attempting SQLAlchemy connection with:")
    print(f"SERVER={server}")
    print(f"DATABASE={database}")
    print(f"UID={username}")
    print(f"Pooling disabled={disable_pooling}")
    print(f"Password length={len(password) if password else 0}")
    print("ODBC connection string:", odbc_str)
    print("Unquoted (quote_plus):", urllib.parse.unquote_plus(encoded_plus))

    try:
        print("Testing raw pyodbc.connect...")
        with pyodbc.connect(odbc_str) as raw_conn:
            cursor = raw_conn.cursor()
            cursor.execute("SELECT 1")
            print("pyodbc SELECT 1 ->", cursor.fetchone())

        print("Testing raw pyodbc.connect with kwargs...")
        with pyodbc.connect(odbc_str, timeout=60, autocommit=False) as raw_conn_kwargs:
            cursor = raw_conn_kwargs.cursor()
            cursor.execute("SELECT 1")
            print("pyodbc SELECT 1 (kwargs) ->", cursor.fetchone())
    except Exception as exc:  # pylint: disable=broad-except
        print("Raw pyodbc connection failed:", exc)

    print("Trying SQLAlchemy with quote_plus encoding...")
    print("URL (quote_plus)=", sqlalchemy_url_plus)
    try:
        engine = create_engine(sqlalchemy_url_plus, connect_args=connect_args, **engine_kwargs)
        with engine.connect() as connection:
            result = connection.execute(text("SELECT 1"))
            scalar = result.scalar_one()
            print("SQLAlchemy SELECT 1 (quote_plus) ->", scalar)
    except Exception as exc:  # pylint: disable=broad-except
        print("quote_plus connection failed:", exc)

    print("Trying SQLAlchemy with quote encoding...")
    print("URL (quote)=", sqlalchemy_url)
    try:
        engine2 = create_engine(sqlalchemy_url, connect_args=connect_args, **engine_kwargs)
        with engine2.connect() as connection:
            result = connection.execute(text("SELECT 1"))
            scalar = result.scalar_one()
            print("SQLAlchemy SELECT 1 (quote) ->", scalar)
    except Exception as exc:  # pylint: disable=broad-except
        print("quote connection failed:", exc)

    print("Trying SQLAlchemy with creator lambda...")
    try:
        engine3 = create_engine(
            "mssql+pyodbc://",
            creator=lambda: pyodbc.connect(odbc_str, **connect_args),
            **engine_kwargs,
        )
        with engine3.connect() as connection:
            result = connection.execute(text("SELECT 1"))
            scalar = result.scalar_one()
            print("SQLAlchemy SELECT 1 (creator) ->", scalar)
    except Exception as exc:  # pylint: disable=broad-except
        print("creator connection failed:", exc)


if __name__ == "__main__":
    main()
