import type { AuthenticatedUser } from '../../common/types/auth-user';
import { QueueServerScanDto } from './dto/queue-server-scan.dto';
import { ReportServerScanDto } from './dto/report-server-scan.dto';
import { TelemetryPayloadDto } from './dto/telemetry-payload.dto';
import type { AgentSessionContext } from './guards/agent-session.guard';
import { ServerScanService } from './server-scan.service';
export declare class ServerScanController {
    private readonly serverScanService;
    constructor(serverScanService: ServerScanService);
    queueScan(serverId: string, payload: QueueServerScanDto, user: AuthenticatedUser): Promise<{
        result: {
            summaryJson: import("@prisma/client/runtime/library").JsonValue;
            createdAt: Date;
            rawLog: string | null;
            storageMetricsJson: import("@prisma/client/runtime/library").JsonValue;
            memoryMetricsJson: import("@prisma/client/runtime/library").JsonValue;
            securityFindingsJson: import("@prisma/client/runtime/library").JsonValue;
        } | null;
        id: string;
        status: import(".prisma/client").$Enums.ServerScanStatus;
        startedAt: Date | null;
        completedAt: Date | null;
        serverId: string;
        agentId: string | null;
        playbook: string;
        parameters: import("@prisma/client/runtime/library").JsonValue;
        queuedAt: Date;
        failureReason: string | null;
        creditsCharged: number | null;
        agent: {
            id: string;
            status: import(".prisma/client").$Enums.ServerAgentStatus;
            lastSeenAt: Date | null;
        } | null;
    }>;
    listScans(serverId: string, user: AuthenticatedUser): Promise<{
        result: {
            summaryJson: import("@prisma/client/runtime/library").JsonValue;
            createdAt: Date;
            rawLog: string | null;
            storageMetricsJson: import("@prisma/client/runtime/library").JsonValue;
            memoryMetricsJson: import("@prisma/client/runtime/library").JsonValue;
            securityFindingsJson: import("@prisma/client/runtime/library").JsonValue;
        } | null;
        id: string;
        status: import(".prisma/client").$Enums.ServerScanStatus;
        startedAt: Date | null;
        completedAt: Date | null;
        serverId: string;
        agentId: string | null;
        playbook: string;
        parameters: import("@prisma/client/runtime/library").JsonValue;
        queuedAt: Date;
        failureReason: string | null;
        creditsCharged: number | null;
        agent: {
            id: string;
            status: import(".prisma/client").$Enums.ServerAgentStatus;
            lastSeenAt: Date | null;
        } | null;
    }[]>;
    fetchNext(agent: AgentSessionContext): Promise<{
        id: string;
        status: import(".prisma/client").$Enums.ServerScanStatus;
        startedAt: Date | null;
        serverId: string;
        playbook: string;
        parameters: import("@prisma/client/runtime/library").JsonValue;
        queuedAt: Date;
    } | null>;
    submitReport(scanId: string, payload: ReportServerScanDto, agent: AgentSessionContext): Promise<{
        id: string;
        status: "COMPLETED" | "FAILED";
        completedAt: Date;
    }>;
    ingestTelemetry(payload: TelemetryPayloadDto, agent: AgentSessionContext): Promise<{
        id: string;
        serverId: string;
        agentId: string | null;
        creditsCharged: number | null;
        cpuPercent: number | null;
        memoryPercent: number | null;
        diskPercent: number | null;
        collectedAt: Date;
    }>;
}
//# sourceMappingURL=server-scan.controller.d.ts.map