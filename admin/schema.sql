-- Destiny 2 Vault Database Schema (Azure SQL / T-SQL)
-- Source of truth: ItemModel / CharacterModel / VaultModel

-- ==========================================================
-- Users
-- ==========================================================
CREATE TABLE dbo.Users (
    user_id         BIGINT        IDENTITY(1,1) NOT NULL PRIMARY KEY,   -- Platform-agnostic internal id
    membership_id   NVARCHAR(50)  NOT NULL,               -- Bungie membershipId
    membership_type NVARCHAR(20)  NOT NULL,               -- Bungie membershipType
    display_name    NVARCHAR(100) NULL,                   -- Bungie display name
    created_at      DATETIME2     NOT NULL DEFAULT SYSUTCDATETIME() -- Creation timestamp
);

-- ==========================================================
-- Vaults
-- ==========================================================
CREATE TABLE dbo.Vaults (
    vault_id     BIGINT        IDENTITY(1,1) NOT NULL PRIMARY KEY,      -- Vault ID
    user_id      BIGINT        NOT NULL,                  -- FK to Users
    created_at   DATETIME2     NOT NULL DEFAULT SYSUTCDATETIME(), -- Creation timestamp
    updated_at   DATETIME2     NOT NULL DEFAULT SYSUTCDATETIME(), -- Last update timestamp
    CONSTRAINT FK_Vaults_Users FOREIGN KEY (user_id) REFERENCES dbo.Users(user_id)
);

-- ==========================================================
-- Characters
-- ==========================================================
CREATE TABLE dbo.Characters (
    character_id            BIGINT        NOT NULL PRIMARY KEY, -- Destiny 2 character ID
    user_id                 BIGINT        NOT NULL,             -- FK to Users
    class_type              NVARCHAR(50)  NULL,                 -- Titan/Hunter/Warlock (label)
    light                   INT           NULL,                 -- Power level
    race_hash               BIGINT        NULL,                 -- Destiny race hash
    artifact_item_hash      BIGINT        NULL,                 -- Seasonal artifact definition hash
    artifact_power_bonus    INT           NULL,                 -- Seasonal artifact power bonus
    artifact_updated_at     DATETIME2     NULL,                 -- Last time artifact info updated
    created_at              DATETIME2     NOT NULL DEFAULT SYSUTCDATETIME(), -- Creation timestamp
    CONSTRAINT FK_Characters_Users FOREIGN KEY (user_id) REFERENCES dbo.Users(user_id)
);
CREATE INDEX IX_Characters_ArtifactHash ON dbo.Characters(artifact_item_hash);
CREATE INDEX IX_Characters_UserId ON dbo.Characters(user_id);

-- ==========================================================
-- Items
-- ==========================================================
CREATE TABLE dbo.Items (
    item_id           BIGINT        IDENTITY(1,1) NOT NULL PRIMARY KEY,   -- Internal app id
    character_id      BIGINT        NULL,                   -- FK to Characters
    vault_id          BIGINT        NULL,                   -- FK to Vaults
    item_hash         BIGINT        NOT NULL,               -- Destiny item hash
    item_instance_id  BIGINT        NULL,                   -- Bungie instance id
    name              NVARCHAR(100) NULL,                   -- Item name
    type              NVARCHAR(50)  NULL,                   -- Item type label
    tier              NVARCHAR(50)  NULL,                   -- Item tier label
    power_value       INT           NULL,                   -- Power value
    is_equipped       BIT           NOT NULL DEFAULT 0,     -- Equipped flag
    content_hash      NVARCHAR(64)  NULL,                   -- Content hash
    collectible_hash  BIGINT        NULL,                   -- Collectible hash
    power_cap_hash    BIGINT        NULL,                   -- Power cap hash
    season_hash       BIGINT        NULL,                   -- Season hash
    updated_at        DATETIME2     NOT NULL DEFAULT SYSUTCDATETIME(), -- Last update timestamp
    created_at        DATETIME2     NOT NULL DEFAULT SYSUTCDATETIME(), -- Creation timestamp
    CONSTRAINT FK_Items_Characters FOREIGN KEY (character_id) REFERENCES dbo.Characters(character_id),
    CONSTRAINT FK_Items_Vaults FOREIGN KEY (vault_id) REFERENCES dbo.Vaults(vault_id)
);
CREATE INDEX IX_Items_Character_Equipped ON dbo.Items(character_id, is_equipped);
CREATE INDEX IX_Items_ItemHash ON dbo.Items(item_hash);
CREATE INDEX IX_Items_InstanceId ON dbo.Items(item_instance_id);

-- ==========================================================
-- ItemStats
-- ==========================================================
CREATE TABLE dbo.ItemStats (
    item_id   BIGINT       NOT NULL,                       -- FK to Items
    stat_hash BIGINT       NOT NULL,                       -- Destiny stat hash
    stat_name NVARCHAR(100) NULL,                          -- Stat name
    stat_value INT          NOT NULL,                      -- Stat value
    CONSTRAINT PK_ItemStats PRIMARY KEY (item_id, stat_hash),
    CONSTRAINT FK_ItemStats_Items FOREIGN KEY (item_id) REFERENCES dbo.Items(item_id)
);
CREATE INDEX IX_ItemStats_StatHash_Value ON dbo.ItemStats(stat_hash, stat_value DESC);
CREATE INDEX IX_ItemStats_ItemId ON dbo.ItemStats(item_id);

-- ==========================================================
-- ItemSockets
-- ==========================================================
CREATE TABLE dbo.ItemSockets (
    item_id        BIGINT      NOT NULL,                   -- FK to Items
    socket_index   INT         NOT NULL,                   -- Socket index
    socket_type_hash BIGINT    NULL,                       -- Socket type hash
    category_name  NVARCHAR(100) NULL,                     -- Socket category name
    is_visible     BIT         NOT NULL DEFAULT 1,         -- Visibility flag
    is_enabled     BIT         NOT NULL DEFAULT 1,         -- Enabled flag
    CONSTRAINT PK_ItemSockets PRIMARY KEY (item_id, socket_index),
    CONSTRAINT FK_ItemSockets_Items FOREIGN KEY (item_id) REFERENCES dbo.Items(item_id)
);
CREATE INDEX IX_ItemSockets_ItemId ON dbo.ItemSockets(item_id);

-- ==========================================================
-- ItemPlugs
-- ==========================================================
CREATE TABLE dbo.ItemPlugs (
    item_id      BIGINT     NOT NULL,                      -- FK to Items
    socket_index INT        NOT NULL,                      -- Socket index
    plug_hash    BIGINT     NOT NULL,                      -- Plug hash
    plug_name    NVARCHAR(100) NULL,                       -- Plug name
    plug_icon    NVARCHAR(255) NULL,                       -- Plug icon
    is_equipped  BIT        NOT NULL DEFAULT 0,            -- Equipped flag
    CONSTRAINT PK_ItemPlugs PRIMARY KEY (item_id, socket_index, plug_hash),
    CONSTRAINT FK_ItemPlugs_ItemSockets FOREIGN KEY (item_id, socket_index)
        REFERENCES dbo.ItemSockets(item_id, socket_index)
);
CREATE INDEX IX_ItemPlugs_ItemId ON dbo.ItemPlugs(item_id);
CREATE INDEX IX_ItemPlugs_SocketIndex ON dbo.ItemPlugs(socket_index);
CREATE INDEX IX_ItemPlugs_PlugHash ON dbo.ItemPlugs(plug_hash);

-- ==========================================================
-- ItemSocketChoices
-- ==========================================================
CREATE TABLE dbo.ItemSocketChoices (
    instance_id   BIGINT       NOT NULL,                   -- FK to Items.item_instance_id
    socket_index  INT          NOT NULL,                   -- Socket index
    plug_hash     BIGINT       NOT NULL,                   -- Plug hash
    plug_name     NVARCHAR(100) NULL,                      -- Plug name
    CONSTRAINT PK_ItemSocketChoices PRIMARY KEY (instance_id, socket_index, plug_hash)
);
CREATE INDEX IX_ItemSocketChoices_Plug ON dbo.ItemSocketChoices(plug_hash);
CREATE INDEX IX_ItemSocketChoices_Inst ON dbo.ItemSocketChoices(instance_id);

-- ==========================================================
-- ItemSandboxPerks
-- ==========================================================
CREATE TABLE dbo.ItemSandboxPerks (
    instance_id       BIGINT       NOT NULL,                -- FK to Items.item_instance_id
    sandbox_perk_hash BIGINT       NOT NULL,                -- Sandbox perk hash
    name              NVARCHAR(100) NULL,                   -- Perk name
    icon              NVARCHAR(255) NULL,                   -- Perk icon
    is_active         BIT          NOT NULL DEFAULT 0,      -- Active flag
    is_visible        BIT          NOT NULL DEFAULT 0,      -- Visible flag
    CONSTRAINT PK_ItemSandboxPerks PRIMARY KEY (instance_id, sandbox_perk_hash)
);
CREATE INDEX IX_ItemSandboxPerks_Hash ON dbo.ItemSandboxPerks(sandbox_perk_hash);
CREATE INDEX IX_ItemSandboxPerks_Inst ON dbo.ItemSandboxPerks(instance_id);

-- ==========================================================
-- ItemEnergy
-- ==========================================================
CREATE TABLE dbo.ItemEnergy (
    instance_id       BIGINT       NOT NULL PRIMARY KEY,    -- FK to Items.item_instance_id
    energy_type_hash  BIGINT       NULL,                    -- Energy type hash
    energy_type_name  NVARCHAR(50) NULL,                    -- Energy type name
    capacity          INT          NULL,                    -- Energy capacity
    used              INT          NULL,                    -- Energy used
    unused            INT          NULL                     -- Energy unused
);

-- ==========================================================
-- ItemSocketLayout
-- ==========================================================
CREATE TABLE dbo.ItemSocketLayout (
    item_hash     BIGINT       NOT NULL,                    -- Destiny item hash
    socket_index  INT          NOT NULL,                    -- Socket index
    category_name NVARCHAR(100) NULL,                       -- Socket category name
    CONSTRAINT PK_ItemSocketLayout PRIMARY KEY (item_hash, socket_index)
);
CREATE INDEX IX_ItemSocketLayout_ItemHash ON dbo.ItemSocketLayout(item_hash);
