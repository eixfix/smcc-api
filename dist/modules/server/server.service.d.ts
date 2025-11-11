import type { Prisma } from '@prisma/client';
import { PrismaService } from '../../prisma/prisma.service';
import type { AuthenticatedUser } from '../../common/types/auth-user';
import { CreateServerDto } from './dto/create-server.dto';
import { UpdateServerDto } from './dto/update-server.dto';
export declare class ServerService {
    private readonly prisma;
    constructor(prisma: PrismaService);
    create(payload: CreateServerDto, user: AuthenticatedUser): Promise<{
        organization: {
            id: string;
            name: string;
            credits: number;
            lastCreditedAt: Date;
            lastDebitAt: Date | null;
            scanSuspendedAt: Date | null;
        };
        id: string;
        createdAt: Date;
        updatedAt: Date;
        name: string;
        description: string | null;
        scans: {
            id: string;
            status: import(".prisma/client").$Enums.ServerScanStatus;
            startedAt: Date | null;
            completedAt: Date | null;
            playbook: string;
            parameters: Prisma.JsonValue;
            queuedAt: Date;
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
        hostname: string | null;
        allowedIp: string | null;
        isSuspended: boolean;
        agents: {
            id: string;
            status: import(".prisma/client").$Enums.ServerAgentStatus;
            accessKey: string;
            issuedAt: Date;
            expiresAt: Date | null;
            lastSeenAt: Date | null;
        }[];
    }>;
    findAll(user: AuthenticatedUser, organizationId?: string): Promise<{
        organization: {
            id: string;
            name: string;
            credits: number;
            lastCreditedAt: Date;
            lastDebitAt: Date | null;
            scanSuspendedAt: Date | null;
        };
        id: string;
        createdAt: Date;
        updatedAt: Date;
        name: string;
        description: string | null;
        telemetry: {
            id: string;
            cpuPercent: number | null;
            memoryPercent: number | null;
            diskPercent: number | null;
            rawJson: Prisma.JsonValue;
            collectedAt: Date;
        }[];
        hostname: string | null;
        allowedIp: string | null;
        isSuspended: boolean;
    }[]>;
    findOne(id: string, user: AuthenticatedUser): Promise<{
        organization: {
            id: string;
            name: string;
            credits: number;
            lastCreditedAt: Date;
            lastDebitAt: Date | null;
            scanSuspendedAt: Date | null;
        };
        id: string;
        createdAt: Date;
        updatedAt: Date;
        name: string;
        description: string | null;
        scans: {
            id: string;
            status: import(".prisma/client").$Enums.ServerScanStatus;
            startedAt: Date | null;
            completedAt: Date | null;
            playbook: string;
            parameters: Prisma.JsonValue;
            queuedAt: Date;
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
        hostname: string | null;
        allowedIp: string | null;
        isSuspended: boolean;
        agents: {
            id: string;
            status: import(".prisma/client").$Enums.ServerAgentStatus;
            accessKey: string;
            issuedAt: Date;
            expiresAt: Date | null;
            lastSeenAt: Date | null;
        }[];
    }>;
    update(id: string, payload: UpdateServerDto, user: AuthenticatedUser): Promise<{
        organization: {
            id: string;
            name: string;
            credits: number;
            lastCreditedAt: Date;
            lastDebitAt: Date | null;
            scanSuspendedAt: Date | null;
        };
        id: string;
        createdAt: Date;
        updatedAt: Date;
        name: string;
        description: string | null;
        scans: {
            id: string;
            status: import(".prisma/client").$Enums.ServerScanStatus;
            startedAt: Date | null;
            completedAt: Date | null;
            playbook: string;
            parameters: Prisma.JsonValue;
            queuedAt: Date;
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
        hostname: string | null;
        allowedIp: string | null;
        isSuspended: boolean;
        agents: {
            id: string;
            status: import(".prisma/client").$Enums.ServerAgentStatus;
            accessKey: string;
            issuedAt: Date;
            expiresAt: Date | null;
            lastSeenAt: Date | null;
        }[];
    }>;
    setSuspension(id: string, isSuspended: boolean, user: AuthenticatedUser): Promise<{
        organization: {
            id: string;
            name: string;
            credits: number;
            lastCreditedAt: Date;
            lastDebitAt: Date | null;
            scanSuspendedAt: Date | null;
        };
        id: string;
        createdAt: Date;
        updatedAt: Date;
        name: string;
        description: string | null;
        scans: {
            id: string;
            status: import(".prisma/client").$Enums.ServerScanStatus;
            startedAt: Date | null;
            completedAt: Date | null;
            playbook: string;
            parameters: Prisma.JsonValue;
            queuedAt: Date;
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
        hostname: string | null;
        allowedIp: string | null;
        isSuspended: boolean;
        agents: {
            id: string;
            status: import(".prisma/client").$Enums.ServerAgentStatus;
            accessKey: string;
            issuedAt: Date;
            expiresAt: Date | null;
            lastSeenAt: Date | null;
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