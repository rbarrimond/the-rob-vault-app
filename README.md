# The R.oB. Vault App

The R.oB. Vault App is an Azure Function App and Jupyter-based assistant for Destiny 2 players. It provides secure access to your Destiny 2 vault, character data, and manifest information using the Bungie API.

## Features

- Azure Functions for authentication, session management, and data retrieval from Bungie
- Secure storage of session and vault data using Azure Table Storage and Blob Storage
- Jupyter notebook integration for interactive exploration of Destiny 2 data
- OAuth2 authentication flow for Bungie API access
- Example notebooks for querying and analyzing your Destiny 2 inventory

## Getting Started

1. **Install dependencies:**
   - See `requirements.txt` for required Python packages.
2. **Configure environment variables:**
   - Set `BUNGIE_API_KEY`, `AZURE_STORAGE_CONNECTION_STRING`, and OAuth credentials in your environment or `local.settings.json`.
3. **Run locally:**
   - Use Azure Functions Core Tools or VS Code to start the function app.
4. **Explore with Jupyter:**
   - Use the provided notebooks to interact with your Destiny 2 data.

## Project Structure

- `function_app.py` — Main Azure Function App code
- `explore_valut.ipynb` — Example Jupyter notebook for data exploration
- `requirements.txt` — Python dependencies
- `local.settings.json` — Local development settings (not for production)

## Security

- Do not commit secrets or credentials to source control.
- Use Azure Key Vault or environment variables for production secrets.

## License

This project is for personal and educational use. Not affiliated with Bungie.
