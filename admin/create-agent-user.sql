-- create-agent-user.sql
-- Securely create the agent user for Azure SQL using a password from Azure Key Vault
-- Usage: Run this script after retrieving the password from Key Vault via automation (Azure CLI, PowerShell, etc)


-- Use sqlcmd variable substitution for AGENT_PASSWORD
CREATE USER robvaultagent WITH PASSWORD = '$(AGENT_PASSWORD)';
ALTER ROLE db_datareader ADD MEMBER robvaultagent;
ALTER ROLE db_datawriter ADD MEMBER robvaultagent;

-- Example Azure CLI command to retrieve password:

-- See get-agent-password.sh for retrieving password and setting AGENT_PASSWORD

-- Example usage in automation:

-- Example usage:
-- source get-agent-password.sh <keyvault-name>
-- sqlcmd -S <server> -d <database> -U <admin> -P <admin-password> -v AGENT_PASSWORD="$AGENT_PASSWORD" -i create-agent-user.sql
