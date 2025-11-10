SET @hasCustomVus := (
  SELECT COUNT(*)
  FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'tasks'
    AND COLUMN_NAME = 'customVus'
);

SET @hasDurationSeconds := (
  SELECT COUNT(*)
  FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'tasks'
    AND COLUMN_NAME = 'durationSeconds'
);

SET @addCustomVus := IF(
  @hasCustomVus = 0,
  'ALTER TABLE `tasks` ADD COLUMN `customVus` INT NULL',
  'SELECT 1'
);
PREPARE addCustomStmt FROM @addCustomVus;
EXECUTE addCustomStmt;
DEALLOCATE PREPARE addCustomStmt;

SET @addDurationSeconds := IF(
  @hasDurationSeconds = 0,
  'ALTER TABLE `tasks` ADD COLUMN `durationSeconds` INT NULL',
  'SELECT 1'
);
PREPARE addDurationStmt FROM @addDurationSeconds;
EXECUTE addDurationStmt;
DEALLOCATE PREPARE addDurationStmt;
