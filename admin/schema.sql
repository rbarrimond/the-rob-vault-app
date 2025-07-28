-- Destiny 2 Vault & Character Data Schema
-- For Azure SQL Database (Serverless)

CREATE TABLE dbo.Users (
    user_id BIGINT PRIMARY KEY,
    membership_id NVARCHAR(50) NOT NULL,
    membership_type NVARCHAR(20) NOT NULL,
    display_name NVARCHAR(100),
    created_at DATETIME2 DEFAULT SYSDATETIME()
);

CREATE TABLE dbo.Characters (
    character_id BIGINT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    class_type NVARCHAR(50),
    light INT,
    race_hash BIGINT,
    FOREIGN KEY (user_id) REFERENCES dbo.Users(user_id)
);

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

CREATE TABLE dbo.ItemStats (
    item_id BIGINT NOT NULL,
    stat_hash BIGINT NOT NULL,
    stat_name NVARCHAR(100),
    stat_value INT,
    PRIMARY KEY (item_id, stat_hash),
    FOREIGN KEY (item_id) REFERENCES dbo.Items(item_id)
);

CREATE TABLE dbo.ItemPerks (
    item_id BIGINT NOT NULL,
    perk_hash BIGINT NOT NULL,
    perk_name NVARCHAR(100),
    description NVARCHAR(255),
    icon NVARCHAR(255),
    PRIMARY KEY (item_id, perk_hash),
    FOREIGN KEY (item_id) REFERENCES dbo.Items(item_id)
);

CREATE TABLE dbo.ItemMods (
    item_id BIGINT NOT NULL,
    mod_hash BIGINT NOT NULL,
    mod_name NVARCHAR(100),
    description NVARCHAR(255),
    icon NVARCHAR(255),
    PRIMARY KEY (item_id, mod_hash),
    FOREIGN KEY (item_id) REFERENCES dbo.Items(item_id)
);

CREATE TABLE dbo.ItemMasterwork (
    item_id BIGINT PRIMARY KEY,
    masterwork_hash BIGINT,
    masterwork_name NVARCHAR(100),
    description NVARCHAR(255),
    icon NVARCHAR(255),
    FOREIGN KEY (item_id) REFERENCES dbo.Items(item_id)
);

CREATE INDEX IX_Characters_UserId ON dbo.Characters(user_id);
CREATE INDEX IX_Items_CharacterId ON dbo.Items(character_id);
CREATE INDEX IX_ItemStats_ItemId ON dbo.ItemStats(item_id);
CREATE INDEX IX_ItemPerks_ItemId ON dbo.ItemPerks(item_id);
CREATE INDEX IX_ItemMods_ItemId ON dbo.ItemMods(item_id);
CREATE INDEX IX_ItemMasterwork_ItemId ON dbo.ItemMasterwork(item_id);

-- Agent user creation is handled by deployment automation (see create-agent-user.sql)
