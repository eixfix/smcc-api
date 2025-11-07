-- Add columns to organizations for scan credit tracking
ALTER TABLE `organizations`
  ADD COLUMN `lastCreditedAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  ADD COLUMN `lastDebitAt` DATETIME(3) NULL,
  ADD COLUMN `scanSuspendedAt` DATETIME(3) NULL;

-- CreateTable servers
CREATE TABLE `servers` (
    `id` VARCHAR(191) NOT NULL,
    `organizationId` VARCHAR(191) NOT NULL,
    `name` VARCHAR(191) NOT NULL,
    `hostname` VARCHAR(191) NULL,
    `description` VARCHAR(191) NULL,
    `createdById` VARCHAR(191) NULL,
    `isSuspended` BOOLEAN NOT NULL DEFAULT false,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    INDEX `servers_organizationId_name_idx`(`organizationId`, `name`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable server_agents
CREATE TABLE `server_agents` (
    `id` VARCHAR(191) NOT NULL,
    `serverId` VARCHAR(191) NOT NULL,
    `hashedToken` VARCHAR(191) NOT NULL,
    `issuedById` VARCHAR(191) NULL,
    `issuedAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `expiresAt` DATETIME(3) NULL,
    `lastSeenAt` DATETIME(3) NULL,
    `status` ENUM('ACTIVE', 'REVOKED', 'EXPIRED') NOT NULL DEFAULT 'ACTIVE',

    INDEX `server_agents_serverId_status_idx`(`serverId`, `status`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable server_scans
CREATE TABLE `server_scans` (
    `id` VARCHAR(191) NOT NULL,
    `serverId` VARCHAR(191) NOT NULL,
    `agentId` VARCHAR(191) NULL,
    `playbook` VARCHAR(191) NOT NULL,
    `parameters` JSON NULL,
    `status` ENUM('QUEUED', 'RUNNING', 'COMPLETED', 'FAILED', 'TIMED_OUT') NOT NULL DEFAULT 'QUEUED',
    `queuedAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `startedAt` DATETIME(3) NULL,
    `completedAt` DATETIME(3) NULL,
    `failureReason` VARCHAR(191) NULL,
    `creditsCharged` INT NULL,

    INDEX `server_scans_serverId_queuedAt_idx`(`serverId`, `queuedAt`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable server_scan_results
CREATE TABLE `server_scan_results` (
    `scanId` VARCHAR(191) NOT NULL,
    `summaryJson` JSON NULL,
    `rawLog` LONGTEXT NULL,
    `storageMetricsJson` JSON NULL,
    `memoryMetricsJson` JSON NULL,
    `securityFindingsJson` JSON NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    PRIMARY KEY (`scanId`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable server_telemetry
CREATE TABLE `server_telemetry` (
    `id` VARCHAR(191) NOT NULL,
    `serverId` VARCHAR(191) NOT NULL,
    `agentId` VARCHAR(191) NULL,
    `cpuPercent` DOUBLE NULL,
    `memoryPercent` DOUBLE NULL,
    `diskPercent` DOUBLE NULL,
    `rawJson` JSON NULL,
    `creditsCharged` INT NULL,
    `collectedAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `server_telemetry_serverId_collectedAt_idx`(`serverId`, `collectedAt`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- AddForeignKeys
ALTER TABLE `servers` ADD CONSTRAINT `servers_organizationId_fkey` FOREIGN KEY (`organizationId`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE `servers` ADD CONSTRAINT `servers_createdById_fkey` FOREIGN KEY (`createdById`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

ALTER TABLE `server_agents` ADD CONSTRAINT `server_agents_serverId_fkey` FOREIGN KEY (`serverId`) REFERENCES `servers`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE `server_agents` ADD CONSTRAINT `server_agents_issuedById_fkey` FOREIGN KEY (`issuedById`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

ALTER TABLE `server_scans` ADD CONSTRAINT `server_scans_serverId_fkey` FOREIGN KEY (`serverId`) REFERENCES `servers`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE `server_scans` ADD CONSTRAINT `server_scans_agentId_fkey` FOREIGN KEY (`agentId`) REFERENCES `server_agents`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

ALTER TABLE `server_scan_results` ADD CONSTRAINT `server_scan_results_scanId_fkey` FOREIGN KEY (`scanId`) REFERENCES `server_scans`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE `server_telemetry` ADD CONSTRAINT `server_telemetry_serverId_fkey` FOREIGN KEY (`serverId`) REFERENCES `servers`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE `server_telemetry` ADD CONSTRAINT `server_telemetry_agentId_fkey` FOREIGN KEY (`agentId`) REFERENCES `server_agents`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;
