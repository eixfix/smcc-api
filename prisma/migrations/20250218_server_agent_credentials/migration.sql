-- Add access/secret keys for server agents
ALTER TABLE `server_agents`
  ADD COLUMN `accessKey` VARCHAR(191) NULL,
  ADD COLUMN `hashedSecret` VARCHAR(191) NULL;

-- Backfill legacy records with deterministic access keys and reuse existing hashed tokens
UPDATE `server_agents`
SET `accessKey` = CONCAT('agt_', REPLACE(LEFT(`id`, 24), '-', '')),
    `hashedSecret` = `hashedToken`
WHERE `accessKey` IS NULL;

-- Enforce not-null after backfill
ALTER TABLE `server_agents`
  MODIFY `accessKey` VARCHAR(191) NOT NULL,
  MODIFY `hashedSecret` VARCHAR(191) NOT NULL;

-- Remove old token column
ALTER TABLE `server_agents`
  DROP COLUMN `hashedToken`;

-- Ensure uniqueness of access keys
CREATE UNIQUE INDEX `server_agents_accessKey_key` ON `server_agents`(`accessKey`);
