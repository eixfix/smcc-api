-- CreateTable
CREATE TABLE `agent_update_manifests` (
    `id` VARCHAR(191) NOT NULL,
    `version` VARCHAR(191) NOT NULL,
    `channel` VARCHAR(191) NOT NULL,
    `download_url` VARCHAR(191) NULL,
    `inline_source_b64` LONGTEXT NULL,
    `checksum_algorithm` VARCHAR(191) NULL,
    `checksum_value` VARCHAR(191) NULL,
    `restart_required` BOOLEAN NOT NULL DEFAULT true,
    `min_config_version` VARCHAR(191) NULL,
    `notes` TEXT NULL,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `created_by_id` VARCHAR(191) NULL,
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateIndex
CREATE INDEX `agent_update_manifests_version_channel_idx` ON `agent_update_manifests`(`version`, `channel`);

-- AddForeignKey
ALTER TABLE `agent_update_manifests` ADD CONSTRAINT `agent_update_manifests_created_by_id_fkey` FOREIGN KEY (`created_by_id`) REFERENCES `users`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;
