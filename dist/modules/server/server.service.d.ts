import type { Prisma } from '@prisma/client';
import { PrismaService } from '../../prisma/prisma.service';
import type { AuthenticatedUser } from '../../common/types/auth-user';
import { CreateServerDto } from './dto/create-server.dto';
import { UpdateServerDto } from './dto/update-server.dto';
export declare class ServerService {
    private readonly prisma;
    constructor(prisma: PrismaService);
    create(payload: CreateServerDto, user: AuthenticatedUser): Promise<{
        id: string;
        name: string;
        hostname: string | null;
        allowedIp: string | null;
        description: string | null;
        isSuspended: boolean;
        createdAt: Date;
        updatedAt: Date;
        organization: {
            id: string;
            name: string;
            credits: number;
            lastCreditedAt: Date;
            lastDebitAt: Date | null;
            scanSuspendedAt: Date | null;
        };
        agents: {
            id: string;
            accessKey: string;
            issuedAt: Date;
            expiresAt: Date | null;
            lastSeenAt: Date | null;
            status: import(".prisma/client").$Enums.ServerAgentStatus;
        }[];
        scans: {
            id: string;
            status: import(".prisma/client").$Enums.ServerScanStatus;
            playbook: string;
            parameters: Prisma.JsonValue;
            queuedAt: Date;
            startedAt: Date | null;
            completedAt: Date | null;
            failureReason: string | null;
            creditsCharged: number | null;
            agent: {
                id: string;
                status: import(".prisma/client").$Enums.ServerAgentStatus;
            } | null;
        }[];
        telemetry: {
            id: string;
            cpuPercent: number | null;
            memoryPercent: number | null;
            diskPercent: number | null;
            rawJson: Prisma.JsonValue;
            collectedAt: Date;
        }[];
    }>;
    findAll(user: AuthenticatedUser, organizationId?: string): Promise<{
        id: string;
        name: string;
        hostname: string | null;
        allowedIp: string | null;
        description: string | null;
        isSuspended: boolean;
        createdAt: Date;
        updatedAt: Date;
        organization: {
            id: string;
            name: string;
            credits: number;
            lastCreditedAt: Date;
            lastDebitAt: Date | null;
            scanSuspendedAt: Date | null;
        };
        telemetry: {
            id: string;
            cpuPercent: number | null;
            memoryPercent: number | null;
            diskPercent: number | null;
            rawJson: Prisma.JsonValue;
            collectedAt: Date;
        }[];
    }[]>;
    findOne(id: string, user: AuthenticatedUser): Promise<{
        id: string;
        name: string;
        hostname: string | null;
        allowedIp: string | null;
        description: string | null;
        isSuspended: boolean;
        createdAt: Date;
        updatedAt: Date;
        organization: {
            id: string;
            name: string;
            credits: number;
            lastCreditedAt: Date;
            lastDebitAt: Date | null;
            scanSuspendedAt: Date | null;
        };
        agents: {
            id: string;
            accessKey: string;
            issuedAt: Date;
            expiresAt: Date | null;
            lastSeenAt: Date | null;
            status: import(".prisma/client").$Enums.ServerAgentStatus;
        }[];
        scans: {
            id: string;
            status: import(".prisma/client").$Enums.ServerScanStatus;
            playbook: string;
            parameters: Prisma.JsonValue;
            queuedAt: Date;
            startedAt: Date | null;
            completedAt: Date | null;
            failureReason: string | null;
            creditsCharged: number | null;
            agent: {
                id: string;
                status: import(".prisma/client").$Enums.ServerAgentStatus;
            } | null;
        }[];
        telemetry: {
            id: string;
            cpuPercent: number | null;
            memoryPercent: number | null;
            diskPercent: number | null;
            rawJson: Prisma.JsonValue;
            collectedAt: Date;
        }[];
    }>;
    update(id: string, payload: UpdateServerDto, user: AuthenticatedUser): Promise<{
        id: string;
        name: string;
        hostname: string | null;
        allowedIp: string | null;
        description: string | null;
        isSuspended: boolean;
        createdAt: Date;
        updatedAt: Date;
        organization: {
            id: string;
            name: string;
            credits: number;
            lastCreditedAt: Date;
            lastDebitAt: Date | null;
            scanSuspendedAt: Date | null;
        };
        agents: {
            id: string;
            accessKey: string;
            issuedAt: Date;
            expiresAt: Date | null;
            lastSeenAt: Date | null;
            status: import(".prisma/client").$Enums.ServerAgentStatus;
        }[];
        scans: {
            id: string;
            status: import(".prisma/client").$Enums.ServerScanStatus;
            playbook: string;
            parameters: Prisma.JsonValue;
            queuedAt: Date;
            startedAt: Date | null;
            completedAt: Date | null;
            failureReason: string | null;
            creditsCharged: number | null;
            agent: {
                id: string;
                status: import(".prisma/client").$Enums.ServerAgentStatus;
            } | null;
        }[];
        telemetry: {
            id: string;
            cpuPercent: number | null;
            memoryPercent: number | null;
            diskPercent: number | null;
            rawJson: Prisma.JsonValue;
            collectedAt: Date;
        }[];
    }>;
    setSuspension(id: string, isSuspended: boolean, user: AuthenticatedUser): Promise<{
        id: string;
        name: string;
        hostname: string | null;
        allowedIp: string | null;
        description: string | null;
        isSuspended: boolean;
        createdAt: Date;
        updatedAt: Date;
        organization: {
            id: string;
            name: string;
            credits: number;
            lastCreditedAt: Date;
            lastDebitAt: Date | null;
            scanSuspendedAt: Date | null;
        };
        agents: {
            id: string;
            accessKey: string;
            issuedAt: Date;
            expiresAt: Date | null;
            lastSeenAt: Date | null;
            status: import(".prisma/client").$Enums.ServerAgentStatus;
        }[];
        scans: {
            id: string;
            status: import(".prisma/client").$Enums.ServerScanStatus;
            playbook: string;
            parameters: Prisma.JsonValue;
            queuedAt: Date;
            startedAt: Date | null;
            completedAt: Date | null;
            failureReason: string | null;
            creditsCharged: number | null;
            agent: {
                id: string;
                status: import(".prisma/client").$Enums.ServerAgentStatus;
            } | null;
        }[];
        telemetry: {
            id: string;
            cpuPercent: number | null;
            memoryPercent: number | null;
            diskPercent: number | null;
            rawJson: Prisma.JsonValue;
            collectedAt: Date;
        }[];
    }>;
    listTelemetry(serverId: string, user: AuthenticatedUser, limit?: number): Promise<{
        id: string;
        cpuPercent: number | null;
        memoryPercent: number | null;
        diskPercent: number | null;
        rawJson: Prisma.JsonValue;
        collectedAt: Date;
    }[]>;
    ensureServerOwnerAccess(serverId: string, user: AuthenticatedUser): Promise<{
        id: string;
        organizationId: string;
    }>;
    private ensureOrganizationReadAccess;
    ensureOrganizationOwnerAccess(organizationId: string, user: AuthenticatedUser): Promise<void>;
    private userCanViewTelemetry;
    private stripTelemetry;
    private getUserMembershipRoleMap;
    private getUserOrganizationRole;
}
//# sourceMappingURL=server.service.d.ts.map