import type { AuthenticatedUser } from '../../common/types/auth-user';
import { CreateServerDto } from './dto/create-server.dto';
import { UpdateServerDto } from './dto/update-server.dto';
import { ServerService } from './server.service';
export declare class ServerController {
    private readonly serverService;
    constructor(serverService: ServerService);
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
            rawJson: import("@prisma/client/runtime/library").JsonValue;
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
            parameters: import("@prisma/client/runtime/library").JsonValue;
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
            rawJson: import("@prisma/client/runtime/library").JsonValue;
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
            parameters: import("@prisma/client/runtime/library").JsonValue;
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
            rawJson: import("@prisma/client/runtime/library").JsonValue;
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
            parameters: import("@prisma/client/runtime/library").JsonValue;
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
            rawJson: import("@prisma/client/runtime/library").JsonValue;
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
    suspend(id: string, user: AuthenticatedUser): Promise<{
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
            parameters: import("@prisma/client/runtime/library").JsonValue;
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
            rawJson: import("@prisma/client/runtime/library").JsonValue;
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
    unsuspend(id: string, user: AuthenticatedUser): Promise<{
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
            parameters: import("@prisma/client/runtime/library").JsonValue;
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
            rawJson: import("@prisma/client/runtime/library").JsonValue;
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
    listTelemetry(id: string, user: AuthenticatedUser, limit?: string): Promise<{
        id: string;
        cpuPercent: number | null;
        memoryPercent: number | null;
        diskPercent: number | null;
        rawJson: import("@prisma/client/runtime/library").JsonValue;
        collectedAt: Date;
    }[]>;
}
//# sourceMappingURL=server.controller.d.ts.map