import { OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import type { Prisma } from '@prisma/client';
import { PrismaService } from '../../prisma/prisma.service';
import type { AuthenticatedUser } from '../../common/types/auth-user';
import { CreateUptimeTargetDto } from './dto/create-uptime-target.dto';
import { TestWebhookDto } from './dto/test-webhook.dto';
import { UpdateUptimeTargetDto } from './dto/update-uptime-target.dto';
import { UptimeNotifierService } from './uptime-notifier.service';
declare const TARGET_WITH_CONTEXT_INCLUDE: {
    readonly organization: {
        readonly select: {
            readonly id: true;
            readonly name: true;
            readonly uptimeWebhookUrl: true;
        };
    };
    readonly project: {
        readonly select: {
            readonly id: true;
            readonly name: true;
            readonly uptimeWebhookUrl: true;
        };
    };
    readonly currentSnapshot: true;
};
type TargetWithContext = Prisma.UptimeTargetGetPayload<{
    include: typeof TARGET_WITH_CONTEXT_INCLUDE;
}>;
export declare class UptimeService implements OnModuleInit, OnModuleDestroy {
    private readonly prisma;
    private readonly notifier;
    private readonly logger;
    private scheduler;
    private readonly digestTracker;
    constructor(prisma: PrismaService, notifier: UptimeNotifierService);
    onModuleInit(): Promise<void>;
    onModuleDestroy(): Promise<void>;
    listTargets(organizationId: string, user: AuthenticatedUser): Promise<TargetWithContext[]>;
    getTarget(organizationId: string, targetId: string, user: AuthenticatedUser): Promise<TargetWithContext & {
        recentChecks: unknown[];
    }>;
    listChecks(organizationId: string, targetId: string, user: AuthenticatedUser, limit?: number): Promise<{
        id: string;
        targetId: string;
        state: import(".prisma/client").$Enums.UptimeState;
        reason: import(".prisma/client").$Enums.UptimeReason;
        reasonDetail: string | null;
        statusCode: number | null;
        latencyMs: number | null;
        tlsExpiresAt: Date | null;
        region: string | null;
        resolvedAddress: string | null;
        checkedAt: Date;
    }[]>;
    createTarget(organizationId: string, payload: CreateUptimeTargetDto, user: AuthenticatedUser): Promise<TargetWithContext>;
    updateTarget(organizationId: string, targetId: string, payload: UpdateUptimeTargetDto, user: AuthenticatedUser): Promise<TargetWithContext>;
    runCheckNow(organizationId: string, targetId: string, user: AuthenticatedUser): Promise<{
        target: {
            organization: {
                id: string;
                name: string;
                uptimeWebhookUrl: string | null;
            };
            project: {
                id: string;
                name: string;
                uptimeWebhookUrl: string | null;
            } | null;
            currentSnapshot: {
                id: string;
                targetId: string;
                state: import(".prisma/client").$Enums.UptimeState;
                reason: import(".prisma/client").$Enums.UptimeReason;
                reasonDetail: string | null;
                updatedAt: Date;
                since: Date;
                lastCheckId: string | null;
            } | null;
        } & {
            id: string;
            region: string | null;
            createdAt: Date;
            updatedAt: Date;
            organizationId: string;
            projectId: string | null;
            serverId: string | null;
            label: string;
            url: string;
            protocol: import(".prisma/client").$Enums.UptimeProtocol;
            sensitivity: import(".prisma/client").$Enums.UptimeSensitivity;
            checkIntervalSeconds: number;
            requestTimeoutMs: number;
            expectedStatus: number | null;
            alertWebhookUrl: string | null;
            isPaused: boolean;
            lastState: import(".prisma/client").$Enums.UptimeState;
            lastReason: import(".prisma/client").$Enums.UptimeReason;
            lastLatencyMs: number | null;
            lastCheckedAt: Date | null;
            lastTlsExpiry: Date | null;
            currentSnapshotId: string | null;
        };
        snapshot: {
            id: string;
            targetId: string;
            state: import(".prisma/client").$Enums.UptimeState;
            reason: import(".prisma/client").$Enums.UptimeReason;
            reasonDetail: string | null;
            updatedAt: Date;
            since: Date;
            lastCheckId: string | null;
        };
        check: {
            id: string;
            targetId: string;
            state: import(".prisma/client").$Enums.UptimeState;
            reason: import(".prisma/client").$Enums.UptimeReason;
            reasonDetail: string | null;
            statusCode: number | null;
            latencyMs: number | null;
            tlsExpiresAt: Date | null;
            region: string | null;
            resolvedAddress: string | null;
            checkedAt: Date;
        };
    }>;
    testWebhook(organizationId: string, targetId: string, payload: TestWebhookDto, user: AuthenticatedUser): Promise<{
        ok: boolean;
    }>;
    runScheduledChecks(): Promise<number>;
    private runProbeForTarget;
    private performCheck;
    private resolveStateFromResponse;
    private mapErrorToState;
    private persistProbeResult;
    private maybeSendDigests;
    private resolveAddress;
    private resolveTlsExpiry;
    private normalizeTargetUrl;
    private daysUntil;
    private toNotificationTarget;
    private ensureTargetInOrganization;
    private ensureProjectInOrganization;
    private ensureServerInOrganization;
    private ensureOrganizationReadAccess;
    private ensureOrganizationOwnerAccess;
    private scheduleNextRun;
}
export {};
//# sourceMappingURL=uptime.service.d.ts.map