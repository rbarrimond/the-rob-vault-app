-- Destiny 2 Vault Database Schema (Azure SQL / T-SQL)
-- Source of truth: ItemModel / CharacterModel / VaultModel
-- Projection tables enable fast queries; all FKs under dbo schema

-- ==========================================================
-- Drop existing (idempotent when re-running in dev)
-- ==========================================================
IF OBJECT_ID('dbo.ItemSocketLayout', 'U') IS NOT NULL DROP TABLE dbo.ItemSocketLayout;
IF OBJECT_ID('dbo.ItemSandboxPerks', 'U') IS NOT NULL DROP TABLE dbo.ItemSandboxPerks;
IF OBJECT_ID('dbo.ItemSocketChoices', 'U') IS NOT NULL DROP TABLE dbo.ItemSocketChoices;
IF OBJECT_ID('dbo.ItemEnergy', 'U') IS NOT NULL DROP TABLE dbo.ItemEnergy;
IF OBJECT_ID('dbo.ItemPlugs', 'U') IS NOT NULL DROP TABLE dbo.ItemPlugs;
IF OBJECT_ID('dbo.ItemSockets', 'U') IS NOT NULL DROP TABLE dbo.ItemSockets;
IF OBJECT_ID('dbo.ItemStats', 'U') IS NOT NULL DROP TABLE dbo.ItemStats;
IF OBJECT_ID('dbo.Vaults', 'U') IS NOT NULL DROP TABLE dbo.Vaults;
IF OBJECT_ID('dbo.Items', 'U') IS NOT NULL DROP TABLE dbo.Items;
-- ==========================================================
-- Vaults
-- ==========================================================
CREATE TABLE dbo.Vaults (
    vault_id     BIGINT        NOT NULL PRIMARY KEY,
    user_id      BIGINT        NOT NULL,
    created_at   DATETIME2     NOT NULL DEFAULT SYSUTCDATETIME(),
    updated_at   DATETIME2     NOT NULL DEFAULT SYSUTCDATETIME(),
    CONSTRAINT FK_Vaults_Users FOREIGN KEY (user_id) REFERENCES dbo.Users(user_id)
);

IF OBJECT_ID('dbo.Characters', 'U') IS NOT NULL DROP TABLE dbo.Characters;
IF OBJECT_ID('dbo.Users', 'U') IS NOT NULL DROP TABLE dbo.Users;

-- ==========================================================
-- Users
-- ==========================================================
CREATE TABLE dbo.Users (
    user_id         BIGINT        NOT NULL PRIMARY KEY,   -- platform-agnostic internal id
    membership_id   NVARCHAR(50)  NOT NULL,                -- Bungie membershipId
    membership_type NVARCHAR(20)  NOT NULL,                -- Bungie membershipType
    display_name    NVARCHAR(100) NULL,
    created_at      DATETIME2     NOT NULL DEFAULT SYSUTCDATETIME()
);

-- ==========================================================
-- Characters
-- ==========================================================
CREATE TABLE dbo.Characters (
    character_id            BIGINT        NOT NULL PRIMARY KEY,
    user_id                 BIGINT        NOT NULL,
    class_type              NVARCHAR(50)  NULL,  -- Titan/Hunter/Warlock (label)
    light                   INT           NULL,  -- power level
    race_hash               BIGINT        NULL,
    artifact_item_hash      BIGINT        NULL,  -- seasonal artifact definition hash (profile-wide; stored per character for convenience)
    artifact_power_bonus    INT           NULL,  -- seasonal artifact power bonus applied to character
    artifact_updated_at     DATETIME2     NULL,  -- last time we saw/updated artifact info
    created_at              DATETIME2     NOT NULL DEFAULT SYSUTCDATETIME(),
    CONSTRAINT FK_Characters_Users FOREIGN KEY (user_id) REFERENCES dbo.Users(user_id)
);
CREATE INDEX IX_Characters_ArtifactHash ON dbo.Characters(artifact_item_hash);
CREATE INDEX IX_Characters_UserId ON dbo.Characters(user_id);

-- ==========================================================
-- Items (authoritative per instance)
-- ==========================================================
CREATE TABLE dbo.Items (
    item_id           BIGINT        NOT NULL PRIMARY KEY,   -- internal app id (can be same as instance or your own)
    character_id      BIGINT        NULL,                   -- owning character (NULL if in vault)
    vault_id          BIGINT        NULL,                   -- owning vault (NULL if not in vault)
    item_hash         BIGINT        NOT NULL,               -- definition hash
    item_instance_id  BIGINT        NULL,                   -- Bungie instance id (nullable for non-instanced)
    name              NVARCHAR(100) NULL,
    type              NVARCHAR(50)  NULL,                   -- weapon/armor type label (optional)
    tier              NVARCHAR(50)  NULL,                   -- Exotic/Legendary/etc. (optional)
    power_value       INT           NULL,                   -- primaryStat.value (attack/defense)
    is_equipped       BIT           NOT NULL DEFAULT 0,
    content_hash      NVARCHAR(64)  NULL,                   -- hash over equipped plugs + stats + energy for idempotent writes
    collectible_hash  BIGINT        NULL,
    power_cap_hash    BIGINT        NULL,
    season_hash       BIGINT        NULL,
    updated_at        DATETIME2     NOT NULL DEFAULT SYSUTCDATETIME(),
    created_at        DATETIME2     NOT NULL DEFAULT SYSUTCDATETIME(),
    CONSTRAINT FK_Items_Characters FOREIGN KEY (character_id) REFERENCES dbo.Characters(character_id),
    CONSTRAINT FK_Items_Vaults FOREIGN KEY (vault_id) REFERENCES dbo.Vaults(vault_id)
);
CREATE INDEX IX_Items_Character_Equipped ON dbo.Items(character_id, is_equipped);
CREATE INDEX IX_Items_ItemHash            ON dbo.Items(item_hash);
CREATE INDEX IX_Items_InstanceId          ON dbo.Items(item_instance_id);

-- ==========================================================
-- ItemStats (304)
-- ==========================================================
CREATE TABLE dbo.ItemStats (
    item_id   BIGINT       NOT NULL,
    stat_hash BIGINT       NOT NULL,
    stat_name NVARCHAR(100) NULL,      -- denormalized for UI
    stat_value INT          NOT NULL,
    CONSTRAINT PK_ItemStats PRIMARY KEY (item_id, stat_hash),
    CONSTRAINT FK_ItemStats_Items FOREIGN KEY (item_id) REFERENCES dbo.Items(item_id)
);
CREATE INDEX IX_ItemStats_StatHash_Value ON dbo.ItemStats(stat_hash, stat_value DESC);
CREATE INDEX IX_ItemStats_ItemId         ON dbo.ItemStats(item_id);

-- ==========================================================
-- ItemSockets (305) — socket rows per instance
-- ==========================================================
CREATE TABLE dbo.ItemSockets (
    item_id        BIGINT      NOT NULL,
    socket_index   INT         NOT NULL,
    socket_type_hash BIGINT    NULL,
    category_name  NVARCHAR(100) NULL,  -- e.g., WEAPON PERKS, ARMOR MODS, ARMOR TIER, ARMOR COSMETICS
    is_visible     BIT         NOT NULL DEFAULT 1,
    is_enabled     BIT         NOT NULL DEFAULT 1,
    CONSTRAINT PK_ItemSockets PRIMARY KEY (item_id, socket_index),
    CONSTRAINT FK_ItemSockets_Items FOREIGN KEY (item_id) REFERENCES dbo.Items(item_id)
);
CREATE INDEX IX_ItemSockets_ItemId ON dbo.ItemSockets(item_id);

-- ==========================================================
-- ItemPlugs — equipped & historical plugs per socket
-- ==========================================================
CREATE TABLE dbo.ItemPlugs (
    item_id      BIGINT     NOT NULL,
    socket_index INT        NOT NULL,
    plug_hash    BIGINT     NOT NULL,
    plug_name    NVARCHAR(100) NULL,   -- denormalized for UI
    plug_icon    NVARCHAR(255) NULL,   -- denormalized for UI
    is_equipped  BIT        NOT NULL DEFAULT 0,
    CONSTRAINT PK_ItemPlugs PRIMARY KEY (item_id, socket_index, plug_hash),
    CONSTRAINT FK_ItemPlugs_ItemSockets FOREIGN KEY (item_id, socket_index)
        REFERENCES dbo.ItemSockets(item_id, socket_index)
);
CREATE INDEX IX_ItemPlugs_ItemId        ON dbo.ItemPlugs(item_id);
CREATE INDEX IX_ItemPlugs_SocketIndex   ON dbo.ItemPlugs(socket_index);
CREATE INDEX IX_ItemPlugs_PlugHash      ON dbo.ItemPlugs(plug_hash);

-- ==========================================================
-- ItemSocketChoices — rolled menu (subset of plugs) from 305.reusablePlugHashes
-- ==========================================================
CREATE TABLE dbo.ItemSocketChoices (
    instance_id   BIGINT       NOT NULL,  -- reference Items.item_instance_id
    socket_index  INT          NOT NULL,
    plug_hash     BIGINT       NOT NULL,
    plug_name     NVARCHAR(100) NULL,
    CONSTRAINT PK_ItemSocketChoices PRIMARY KEY (instance_id, socket_index, plug_hash)
);
CREATE INDEX IX_ItemSocketChoices_Plug ON dbo.ItemSocketChoices(plug_hash);
CREATE INDEX IX_ItemSocketChoices_Inst ON dbo.ItemSocketChoices(instance_id);

-- ==========================================================
-- ItemSandboxPerks (302) — artifact/passive perks active on the instance
-- ==========================================================
CREATE TABLE dbo.ItemSandboxPerks (
    instance_id       BIGINT       NOT NULL,  -- reference Items.item_instance_id
    sandbox_perk_hash BIGINT       NOT NULL,
    name              NVARCHAR(100) NULL,
    icon              NVARCHAR(255) NULL,
    is_active         BIT          NOT NULL DEFAULT 0,
    is_visible        BIT          NOT NULL DEFAULT 0,
    CONSTRAINT PK_ItemSandboxPerks PRIMARY KEY (instance_id, sandbox_perk_hash)
);
CREATE INDEX IX_ItemSandboxPerks_Hash ON dbo.ItemSandboxPerks(sandbox_perk_hash);
CREATE INDEX IX_ItemSandboxPerks_Inst ON dbo.ItemSandboxPerks(instance_id);

-- ==========================================================
-- ItemEnergy (300) — armor energy projection
-- ==========================================================
CREATE TABLE dbo.ItemEnergy (
    instance_id       BIGINT       NOT NULL PRIMARY KEY,  -- reference Items.item_instance_id
    energy_type_hash  BIGINT       NULL,
    energy_type_name  NVARCHAR(50) NULL,
    capacity          INT          NULL,
    used              INT          NULL,
    unused            INT          NULL
);

-- ==========================================================
-- ItemSocketLayout — per item_hash socket categories (definition-level cache)
-- ==========================================================
CREATE TABLE dbo.ItemSocketLayout (
    item_hash     BIGINT       NOT NULL,
    socket_index  INT          NOT NULL,
    category_name NVARCHAR(100) NULL,
    CONSTRAINT PK_ItemSocketLayout PRIMARY KEY (item_hash, socket_index)
);
CREATE INDEX IX_ItemSocketLayout_ItemHash ON dbo.ItemSocketLayout(item_hash);

-- ==========================================================
-- Notes
-- - Items.item_instance_id is nullable for non-instanced defs, but indexed for fast joins when present
-- - Choices/Perks/Energy use instance_id to reflect runtime state independent of internal item_id
-- - Sockets/Plugs use item_id for tight per-instance integrity and foreign keys
-- ==========================================================
