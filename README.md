# The R.oB. Vault App

The R.oB. Vault App is an Azure Function App and assistant for Destiny 2 players. It provides secure, programmatic access to my Destiny 2 vault, character data, and manifest information using the Bungie API.

This app is designed to serve as a backend tool for my custom ChatGPT assistant, Vault Sentinel, exposing a set of API endpoints that enable automated, conversational, and programmatic workflows for Destiny 2 inventory and character management. The API is intended to be consumed by Vault Sentinel or other clients, allowing you to:

- Retrieve, organize, and analyze Destiny 2 vault contents and character data on demand
- Automate repetitive inventory tasks and generate custom reports
- Query Destiny 2 manifest data for item definitions, perks, and metadata
- Securely authenticate and manage sessions with Bungie via OAuth2
- Integrate with the OpenAPI spec and static HTML tool for rapid prototyping or testing

## Prerequisites

- Python 3.10+
- [Azure Functions Core Tools v4](https://learn.microsoft.com/azure/azure-functions/functions-run-local)
- [Azure CLI](https://docs.microsoft.com/cli/azure/install-azure-cli)

## Features & Use Cases

- **ChatGPT Integration:** Acts as a backend tool for my ChatGPT assistant, enabling conversational access to Destiny 2 data and automation via API endpoints.
- **Automated Vault Management:** Retrieve, organize, and analyze my Destiny 2 vault contents using Azure Functions and Python.
- **Character Data Insights:** Access and explore detailed character information, including equipment, stats, and progression.
- **Manifest Data Access:** Query Destiny 2 manifest data for item definitions, perks, and metadata.
- **Secure Session Handling:** Authenticate with Bungie via OAuth2 and manage sessions securely using Azure Table Storage.
- **API-Driven Workflows:** Integrate with the Bungie API to automate repetitive inventory tasks or build custom tools for my Destiny 2 experience.
- **OpenAPI Spec & Static Tool:** Reference the OpenAPI spec and included HTML tool for building or testing integrations.

## Getting Started

1. **Install dependencies:**
   - See `requirements.txt` for required Python packages.
2. **Configure environment variables:**
   - Set `BUNGIE_API_KEY`, `AZURE_STORAGE_CONNECTION_STRING`, and OAuth credentials in my environment or `local.settings.json`.
3. **Run locally:**
   - Use Azure Functions Core Tools or VS Code to start the function app.

## Project Structure

- `function_app.py` — Main Azure Function App code
- `vault_assistant.py` — Assistant logic for Destiny 2 data
- `helpers.py` — Helper functions for Azure and Bungie API
- `requirements.txt` — Python dependencies
- `local.settings.json` — Local development settings (not for production)
- `static/openapi.yaml` — OpenAPI spec for the app
- `static/index.html` — Static HTML tool for the app

## Logging (Local vs Production)

The app uses Python's root logger so Azure Functions can automatically forward traces to Application Insights.

**Production defaults:**

- `host.json` sets `Information` level for all functions to control volume.
- Application Insights sampling enabled (5 items/sec) to reduce ingestion cost.
- Code bootstrap falls back to `LOG_LEVEL=INFO` when the env var is unset.

**Local development adjustments:**

- Set `LOG_LEVEL=DEBUG` in `local.settings.json` (not committed) to see verbose pagination, sizing, and diagnostic traces.
- For temporary deep debugging in production, set App Setting `LOG_LEVEL=DEBUG` and (optionally) introduce a short‑lived host.json override for a single function (e.g., `Function.vault`). Revert after troubleshooting.

**Changing verbosity order of precedence:**

1. `host.json` `logging.logLevel` (host filter – anything below is dropped regardless of code level)
2. `LOG_LEVEL` environment variable (Python root logger level)

If logs seem missing at DEBUG, confirm the host-level filter isn't higher than the code-level.

## License

This project is for personal and educational use. Not affiliated with Bungie.
