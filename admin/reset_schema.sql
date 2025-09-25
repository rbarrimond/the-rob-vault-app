-- Safe reset script to rebuild Destiny 2 Vault schema
-- Drops tables in dependency order so admin/schema.sql can be rerun cleanly.
-- WARNING: this permanently removes all data in the vault schema.

IF OBJECT_ID('dbo.ItemSandboxPerks', 'U') IS NOT NULL DROP TABLE dbo.ItemSandboxPerks;
IF OBJECT_ID('dbo.ItemSocketChoices', 'U') IS NOT NULL DROP TABLE dbo.ItemSocketChoices;
IF OBJECT_ID('dbo.ItemPlugs', 'U') IS NOT NULL DROP TABLE dbo.ItemPlugs;
IF OBJECT_ID('dbo.ItemSockets', 'U') IS NOT NULL DROP TABLE dbo.ItemSockets;
IF OBJECT_ID('dbo.ItemEnergy', 'U') IS NOT NULL DROP TABLE dbo.ItemEnergy;
IF OBJECT_ID('dbo.ItemStats', 'U') IS NOT NULL DROP TABLE dbo.ItemStats;
IF OBJECT_ID('dbo.ItemSocketLayout', 'U') IS NOT NULL DROP TABLE dbo.ItemSocketLayout;
IF OBJECT_ID('dbo.Items', 'U') IS NOT NULL DROP TABLE dbo.Items;
IF OBJECT_ID('dbo.Characters', 'U') IS NOT NULL DROP TABLE dbo.Characters;
IF OBJECT_ID('dbo.Vaults', 'U') IS NOT NULL DROP TABLE dbo.Vaults;
IF OBJECT_ID('dbo.Users', 'U') IS NOT NULL DROP TABLE dbo.Users;
