-- Add allowedIp column to servers for source IP validation
ALTER TABLE `servers`
  ADD COLUMN `allowedIp` VARCHAR(45) NULL AFTER `hostname`;
