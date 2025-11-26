-- Add webhook fields for organization/project level Discord routing
ALTER TABLE `organizations`
    ADD COLUMN `uptimeWebhookUrl` VARCHAR(500) NULL AFTER `scanSuspendedAt`;

ALTER TABLE `projects`
    ADD COLUMN `uptimeWebhookUrl` VARCHAR(500) NULL AFTER `description`;

-- Create uptime monitoring tables for milestone 8.1
CREATE TABLE `uptime_targets` (
    `id` VARCHAR(191) NOT NULL,
    `organizationId` VARCHAR(191) NOT NULL,
    `projectId` VARCHAR(191) NULL,
    `serverId` VARCHAR(191) NULL,
    `label` VARCHAR(191) NOT NULL,
    `url` VARCHAR(500) NOT NULL,
    `protocol` ENUM('HTTP', 'HTTPS') NOT NULL,
    `region` VARCHAR(100) NULL,
    `sensitivity` ENUM('PRODUCTION', 'STAGING') NOT NULL DEFAULT 'PRODUCTION',
    `checkIntervalSeconds` INTEGER NOT NULL DEFAULT 300,
    `requestTimeoutMs` INTEGER NOT NULL DEFAULT 5000,
    `expectedStatus` INTEGER NULL,
    `alertWebhookUrl` VARCHAR(500) NULL,
    `isPaused` BOOLEAN NOT NULL DEFAULT false,
    `lastState` ENUM('UP', 'DEGRADED', 'DOWN', 'UNKNOWN') NOT NULL DEFAULT 'UNKNOWN',
    `lastReason` ENUM('STATUS_CODE', 'TIMEOUT', 'TLS', 'DNS', 'NETWORK', 'UNKNOWN') NOT NULL DEFAULT 'UNKNOWN',
    `lastLatencyMs` INTEGER NULL,
    `lastCheckedAt` DATETIME(3) NULL,
    `lastTlsExpiry` DATETIME(3) NULL,
    `currentSnapshotId` VARCHAR(191) NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    INDEX `uptime_targets_organizationId_url_idx`(`organizationId`, `url`),
    INDEX `uptime_targets_serverId_idx`(`serverId`),
    UNIQUE INDEX `uptime_targets_currentSnapshotId_key`(`currentSnapshotId`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE TABLE `uptime_checks` (
    `id` VARCHAR(191) NOT NULL,
    `targetId` VARCHAR(191) NOT NULL,
    `state` ENUM('UP', 'DEGRADED', 'DOWN', 'UNKNOWN') NOT NULL,
    `reason` ENUM('STATUS_CODE', 'TIMEOUT', 'TLS', 'DNS', 'NETWORK', 'UNKNOWN') NOT NULL,
    `reasonDetail` VARCHAR(500) NULL,
    `statusCode` INTEGER NULL,
    `latencyMs` INTEGER NULL,
    `tlsExpiresAt` DATETIME(3) NULL,
    `region` VARCHAR(100) NULL,
    `resolvedAddress` VARCHAR(191) NULL,
    `checkedAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `uptime_checks_targetId_checkedAt_idx`(`targetId`, `checkedAt`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE TABLE `uptime_status_snapshots` (
    `id` VARCHAR(191) NOT NULL,
    `targetId` VARCHAR(191) NOT NULL,
    `state` ENUM('UP', 'DEGRADED', 'DOWN', 'UNKNOWN') NOT NULL,
    `reason` ENUM('STATUS_CODE', 'TIMEOUT', 'TLS', 'DNS', 'NETWORK', 'UNKNOWN') NOT NULL,
    `reasonDetail` VARCHAR(500) NULL,
    `since` DATETIME(3) NOT NULL,
    `lastCheckId` VARCHAR(191) NULL,
    `updatedAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    INDEX `uptime_status_snapshots_targetId_since_idx`(`targetId`, `since`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

ALTER TABLE `uptime_targets` ADD CONSTRAINT `uptime_targets_organizationId_fkey` FOREIGN KEY (`organizationId`) REFERENCES `organizations`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE `uptime_targets` ADD CONSTRAINT `uptime_targets_projectId_fkey` FOREIGN KEY (`projectId`) REFERENCES `projects`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;
ALTER TABLE `uptime_targets` ADD CONSTRAINT `uptime_targets_serverId_fkey` FOREIGN KEY (`serverId`) REFERENCES `servers`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

ALTER TABLE `uptime_checks` ADD CONSTRAINT `uptime_checks_targetId_fkey` FOREIGN KEY (`targetId`) REFERENCES `uptime_targets`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE `uptime_status_snapshots` ADD CONSTRAINT `uptime_status_snapshots_targetId_fkey` FOREIGN KEY (`targetId`) REFERENCES `uptime_targets`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE `uptime_status_snapshots` ADD CONSTRAINT `uptime_status_snapshots_lastCheckId_fkey` FOREIGN KEY (`lastCheckId`) REFERENCES `uptime_checks`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;
ALTER TABLE `uptime_targets` ADD CONSTRAINT `uptime_targets_currentSnapshotId_fkey` FOREIGN KEY (`currentSnapshotId`) REFERENCES `uptime_status_snapshots`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;
