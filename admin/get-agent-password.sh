#!/bin/bash
# get-agent-password.sh
# Retrieves the agent password from Azure Key Vault and stores it in an environment variable

# Usage: source get-agent-password.sh <keyvault-name>
# Example: source get-agent-password.sh my-keyvault

KEYVAULT_NAME="$1"
SECRET_NAME="robVaultAgentPassword"

if [ -z "$KEYVAULT_NAME" ]; then
  echo "Usage: source get-agent-password.sh <keyvault-name>"
  return 1
fi

export AGENT_PASSWORD=$(az keyvault secret show --vault-name "$KEYVAULT_NAME" --name "$SECRET_NAME" --query value -o tsv)

if [ -z "$AGENT_PASSWORD" ]; then
  echo "Failed to retrieve password from Key Vault."
  return 2
fi

echo "AGENT_PASSWORD environment variable set."
