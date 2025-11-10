import type { AuthenticatedUser } from '../../common/types/auth-user';
import { CreateServerDto } from './dto/create-server.dto';
import { UpdateServerDto } from './dto/update-server.dto';
import { ServerService } from './server.service';
export declare class ServerController {
    private readonly serverService;
    constructor(serverService: ServerService);
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
            creditsCharged: number | null;
            agent: {
                id: string;
                status: import(".prisma/client").$Enums.ServerAgentStatus;
            } | null;
            status: import(".prisma/client").$Enums.ServerScanStatus;
            playbook: string;
            parameters: import("@prisma/client/runtime/library").JsonValue;
            queuedAt: Date;
            startedAt: Date | null;
            completedAt: Date | null;
            failureReason: string | null;
        }[];
        telemetry: {
            id: string;
            cpuPercent: number | null;
            memoryPercent: number | null;
            diskPercent: number | null;
            collectedAt: Date;
        }[];
    }>;
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
            creditsCharged: number | null;
            agent: {
                id: string;
                status: import(".prisma/client").$Enums.ServerAgentStatus;
            } | null;
            status: import(".prisma/client").$Enums.ServerScanStatus;
            playbook: string;
            parameters: import("@prisma/client/runtime/library").JsonValue;
            queuedAt: Date;
            startedAt: Date | null;
            completedAt: Date | null;
            failureReason: string | null;
        }[];
        telemetry: {
            id: string;
            cpuPercent: number | null;
            memoryPercent: number | null;
            diskPercent: number | null;
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
            creditsCharged: number | null;
            agent: {
                id: string;
                status: import(".prisma/client").$Enums.ServerAgentStatus;
            } | null;
            status: import(".prisma/client").$Enums.ServerScanStatus;
            playbook: string;
            parameters: import("@prisma/client/runtime/library").JsonValue;
            queuedAt: Date;
            startedAt: Date | null;
            completedAt: Date | null;
            failureReason: string | null;
        }[];
        telemetry: {
            id: string;
            cpuPercent: number | null;
            memoryPercent: number | null;
            diskPercent: number | null;
            collectedAt: Date;
        }[];
    }>;
    suspend(id: string, user: AuthenticatedUser): Promise<{
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
            creditsCharged: number | null;
            agent: {
                id: string;
                status: import(".prisma/client").$Enums.ServerAgentStatus;
            } | null;
            status: import(".prisma/client").$Enums.ServerScanStatus;
            playbook: string;
            parameters: import("@prisma/client/runtime/library").JsonValue;
            queuedAt: Date;
            startedAt: Date | null;
            completedAt: Date | null;
            failureReason: string | null;
        }[];
        telemetry: {
            id: string;
            cpuPercent: number | null;
            memoryPercent: number | null;
            diskPercent: number | null;
            collectedAt: Date;
        }[];
    }>;
    unsuspend(id: string, user: AuthenticatedUser): Promise<{
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
            creditsCharged: number | null;
            agent: {
                id: string;
                status: import(".prisma/client").$Enums.ServerAgentStatus;
            } | null;
            status: import(".prisma/client").$Enums.ServerScanStatus;
            playbook: string;
            parameters: import("@prisma/client/runtime/library").JsonValue;
            queuedAt: Date;
            startedAt: Date | null;
            completedAt: Date | null;
            failureReason: string | null;
        }[];
        telemetry: {
            id: string;
            cpuPercent: number | null;
            memoryPercent: number | null;
            diskPercent: number | null;
            collectedAt: Date;
        }[];
    }>;
    listTelemetry(id: string, user: AuthenticatedUser, limit?: string): Promise<{
        id: string;
        cpuPercent: number | null;
        memoryPercent: number | null;
        diskPercent: number | null;
        collectedAt: Date;
    }[]>;
}
//# sourceMappingURL=server.controller.d.ts.map