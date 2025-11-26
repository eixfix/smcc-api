import type { AuthenticatedUser } from '../../common/types/auth-user';
import { CreateUptimeTargetDto } from './dto/create-uptime-target.dto';
import { TestWebhookDto } from './dto/test-webhook.dto';
import { UpdateUptimeTargetDto } from './dto/update-uptime-target.dto';
import { UptimeService } from './uptime.service';
export declare class UptimeController {
    private readonly uptimeService;
    constructor(uptimeService: UptimeService);
    listTargets(organizationId: string, user: AuthenticatedUser): Promise<({
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
    })[]>;
    createTarget(organizationId: string, payload: CreateUptimeTargetDto, user: AuthenticatedUser): Promise<{
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
    }>;
    getTarget(organizationId: string, targetId: string, user: AuthenticatedUser): Promise<{
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
    } & {
        recentChecks: unknown[];
    }>;
    updateTarget(organizationId: string, targetId: string, payload: UpdateUptimeTargetDto, user: AuthenticatedUser): Promise<{
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
    }>;
    listChecks(organizationId: string, targetId: string, limit: string | undefined, user: AuthenticatedUser): Promise<{
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
    runCheck(organizationId: string, targetId: string, user: AuthenticatedUser): Promise<{
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
}
//# sourceMappingURL=uptime.controller.d.ts.map