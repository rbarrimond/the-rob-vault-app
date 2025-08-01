
-- Destiny 2 Vault Database Schema
-- Idempotent drops and creates for tables and indexes
-- Tables: Users, Characters, Items, ItemStats, ItemPerks, ItemMods, ItemMasterwork, ItemSockets, ItemPlugs
-- Indexes for efficient querying
-- Sockets and plugs model Destiny 2's item customization system

DROP TABLE IF EXISTS dbo.ItemMasterwork;
DROP TABLE IF EXISTS dbo.ItemMods;
DROP TABLE IF EXISTS dbo.ItemPerks;
DROP TABLE IF EXISTS dbo.ItemStats;
DROP TABLE IF EXISTS dbo.Items;
DROP TABLE IF EXISTS dbo.Characters;
DROP TABLE IF EXISTS dbo.Users;
DROP TABLE IF EXISTS dbo.ItemPlugs;
DROP TABLE IF EXISTS dbo.ItemSockets;

-- Users: Destiny account holders
CREATE TABLE dbo.Users (
    user_id BIGINT PRIMARY KEY,
    membership_id NVARCHAR(50) NOT NULL,
    membership_type NVARCHAR(20) NOT NULL,
    display_name NVARCHAR(100),
    created_at DATETIME2 DEFAULT SYSDATETIME()
);

-- Characters: Destiny characters per user
CREATE TABLE dbo.Characters (
    character_id BIGINT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    class_type NVARCHAR(50),
    light INT,
    race_hash BIGINT,
    FOREIGN KEY (user_id) REFERENCES dbo.Users(user_id)
);

-- Items: Inventory items per character
CREATE TABLE dbo.Items (
    item_id BIGINT PRIMARY KEY,
    character_id BIGINT,
    item_hash BIGINT NOT NULL,
    item_instance_id BIGINT,
    name NVARCHAR(100),
    type NVARCHAR(50),
    tier NVARCHAR(50),
    collectible_hash BIGINT,
    power_cap_hash BIGINT,
    season_hash BIGINT,
    FOREIGN KEY (character_id) REFERENCES dbo.Characters(character_id)
);

-- ItemStats: Base stats for each item
CREATE TABLE dbo.ItemStats (
    item_id BIGINT NOT NULL,
    stat_hash BIGINT NOT NULL,
    stat_name NVARCHAR(100),
    stat_value INT,
    PRIMARY KEY (item_id, stat_hash),
    FOREIGN KEY (item_id) REFERENCES dbo.Items(item_id)
);

-- ItemPerks: Perks available on items
CREATE TABLE dbo.ItemPerks (
    item_id BIGINT NOT NULL,
    perk_hash BIGINT NOT NULL,
    perk_name NVARCHAR(100),
    description NVARCHAR(255),
    icon NVARCHAR(255),
    PRIMARY KEY (item_id, perk_hash),
    FOREIGN KEY (item_id) REFERENCES dbo.Items(item_id)
);

-- ItemMods: Mods available on items
CREATE TABLE dbo.ItemMods (
    item_id BIGINT NOT NULL,
    mod_hash BIGINT NOT NULL,
    mod_name NVARCHAR(100),
    description NVARCHAR(255),
    icon NVARCHAR(255),
    PRIMARY KEY (item_id, mod_hash),
    FOREIGN KEY (item_id) REFERENCES dbo.Items(item_id)
);

-- ItemMasterwork: Masterwork details for items
CREATE TABLE dbo.ItemMasterwork (
    item_id BIGINT PRIMARY KEY,
    masterwork_hash BIGINT,
    masterwork_name NVARCHAR(100),
    description NVARCHAR(255),
    icon NVARCHAR(255),
    FOREIGN KEY (item_id) REFERENCES dbo.Items(item_id)
);

-- ItemSockets: Sockets on items for customization
CREATE TABLE dbo.ItemSockets (
    item_id BIGINT NOT NULL,
    socket_index INT NOT NULL,
    socket_type_hash BIGINT,
    PRIMARY KEY (item_id, socket_index),
    FOREIGN KEY (item_id) REFERENCES dbo.Items(item_id)
);

-- ItemPlugs: Plugs (perks/mods) in sockets, tracks equipped state
CREATE TABLE dbo.ItemPlugs (
    item_id BIGINT NOT NULL,
    socket_index INT NOT NULL,
    plug_hash BIGINT NOT NULL,
    is_equipped BIT NOT NULL DEFAULT 0,
    PRIMARY KEY (item_id, socket_index, plug_hash),
    FOREIGN KEY (item_id, socket_index) REFERENCES dbo.ItemSockets(item_id, socket_index)
);

-- Indexes for efficient lookups
CREATE INDEX IX_Characters_UserId ON dbo.Characters(user_id);
CREATE INDEX IX_Items_CharacterId ON dbo.Items(character_id);
CREATE INDEX IX_ItemStats_ItemId ON dbo.ItemStats(item_id);
CREATE INDEX IX_ItemPerks_ItemId ON dbo.ItemPerks(item_id);
CREATE INDEX IX_ItemMods_ItemId ON dbo.ItemMods(item_id);
CREATE INDEX IX_ItemMasterwork_ItemId ON dbo.ItemMasterwork(item_id);
CREATE INDEX IX_ItemSockets_ItemId ON dbo.ItemSockets(item_id);
CREATE INDEX IX_ItemPlugs_ItemId ON dbo.ItemPlugs(item_id);
CREATE INDEX IX_ItemPlugs_SocketIndex ON dbo.ItemPlugs(socket_index);

-- Agent user creation is handled by deployment automation (see create-agent-user.sql)
