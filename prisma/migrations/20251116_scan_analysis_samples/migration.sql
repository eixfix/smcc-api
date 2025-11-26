-- CreateTable
CREATE TABLE `scan_analysis_samples` (
  `id` VARCHAR(191) NOT NULL,
  `scanId` VARCHAR(191) NOT NULL,
  `serverId` VARCHAR(191) NOT NULL,
  `agentId` VARCHAR(191) NULL,
  `organizationId` VARCHAR(191) NULL,
  `status` VARCHAR(191) NOT NULL,
  `failureReason` VARCHAR(191) NULL,
  `durationSeconds` INT NULL,
  `p95LatencyMs` DOUBLE NULL,
  `averageLatencyMs` DOUBLE NULL,
  `successRate` DOUBLE NULL,
  `cpuPercent` DOUBLE NULL,
  `memoryPercent` DOUBLE NULL,
  `diskPercent` DOUBLE NULL,
  `features` JSON NULL,
  `collectedAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  UNIQUE INDEX `scan_analysis_samples_scanId_key`(`scanId`),
  INDEX `scan_analysis_samples_serverId_collectedAt_idx`(`serverId`, `collectedAt`),
  PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- AddForeignKey
ALTER TABLE `scan_analysis_samples`
ADD CONSTRAINT `scan_analysis_samples_scanId_fkey`
FOREIGN KEY (`scanId`) REFERENCES `server_scans`(`id`)
ON DELETE CASCADE ON UPDATE CASCADE;
