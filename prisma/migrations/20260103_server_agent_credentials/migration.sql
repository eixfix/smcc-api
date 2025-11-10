SET @hasAccessKey := (
  SELECT COUNT(*)
  FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'server_agents'
    AND COLUMN_NAME = 'accessKey'
);

SET @hasHashedSecret := (
  SELECT COUNT(*)
  FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'server_agents'
    AND COLUMN_NAME = 'hashedSecret'
);

SET @addAccessKey := IF(
  @hasAccessKey = 0,
  'ALTER TABLE `server_agents` ADD COLUMN `accessKey` VARCHAR(191) NULL',
  'SELECT 1'
);
PREPARE addAccessKeyStmt FROM @addAccessKey;
EXECUTE addAccessKeyStmt;
DEALLOCATE PREPARE addAccessKeyStmt;

SET @addHashedSecret := IF(
  @hasHashedSecret = 0,
  'ALTER TABLE `server_agents` ADD COLUMN `hashedSecret` VARCHAR(191) NULL',
  'SELECT 1'
);
PREPARE addHashedSecretStmt FROM @addHashedSecret;
EXECUTE addHashedSecretStmt;
DEALLOCATE PREPARE addHashedSecretStmt;

SET @hasHashedToken := (
  SELECT COUNT(*)
  FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'server_agents'
    AND COLUMN_NAME = 'hashedToken'
);

SET @needsBackfill := (
  SELECT COUNT(*)
  FROM `server_agents`
  WHERE `accessKey` IS NULL
);

SET @backfillSql := IF(
  @hasHashedToken > 0 AND @needsBackfill > 0,
  'UPDATE `server_agents` SET `accessKey` = CONCAT(''agt_'', REPLACE(LEFT(`id`, 24), ''-'', '''')), `hashedSecret` = `hashedToken` WHERE `accessKey` IS NULL',
  'SELECT 1'
);
PREPARE backfillStmt FROM @backfillSql;
EXECUTE backfillStmt;
DEALLOCATE PREPARE backfillStmt;

ALTER TABLE `server_agents`
  MODIFY COLUMN `accessKey` VARCHAR(191) NOT NULL,
  MODIFY COLUMN `hashedSecret` VARCHAR(191) NOT NULL;

SET @dropHashedToken := IF(
  @hasHashedToken > 0,
  'ALTER TABLE `server_agents` DROP COLUMN `hashedToken`',
  'SELECT 1'
);
PREPARE dropStmt FROM @dropHashedToken;
EXECUTE dropStmt;
DEALLOCATE PREPARE dropStmt;

SET @indexExists := (
  SELECT COUNT(*)
  FROM INFORMATION_SCHEMA.STATISTICS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'server_agents'
    AND INDEX_NAME = 'server_agents_accessKey_key'
);
SET @createIndex := IF(
  @indexExists = 0,
  'CREATE UNIQUE INDEX `server_agents_accessKey_key` ON `server_agents`(`accessKey`)',
  'SELECT 1'
);
PREPARE indexStmt FROM @createIndex;
EXECUTE indexStmt;
DEALLOCATE PREPARE indexStmt;
