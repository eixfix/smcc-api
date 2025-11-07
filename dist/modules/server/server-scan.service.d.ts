import { Prisma } from '@prisma/client';
import type { AuthenticatedUser } from '../../common/types/auth-user';
import { PrismaService } from '../../prisma/prisma.service';
import { OrganizationCreditService } from '../organization/organization-credit.service';
import type { AgentSessionContext } from './guards/agent-session.guard';
import { QueueServerScanDto } from './dto/queue-server-scan.dto';
import { ReportServerScanDto } from './dto/report-server-scan.dto';
import { TelemetryPayloadDto } from './dto/telemetry-payload.dto';
import { ServerAgentService } from './server-agent.service';
import { ServerService } from './server.service';
export declare class ServerScanService {
    private readonly prisma;
    private readonly creditService;
    private readonly serverService;
    private readonly serverAgentService;
    constructor(prisma: PrismaService, creditService: OrganizationCreditService, serverService: ServerService, serverAgentService: ServerAgentService);
    queueScan(serverId: string, dto: QueueServerScanDto, user: AuthenticatedUser): Promise<{
        result: {
            summaryJson: Prisma.JsonValue;
            createdAt: Date;
            rawLog: string | null;
            storageMetricsJson: Prisma.JsonValue;
            memoryMetricsJson: Prisma.JsonValue;
            securityFindingsJson: Prisma.JsonValue;
        } | null;
        id: string;
        status: import(".prisma/client").$Enums.ServerScanStatus;
        startedAt: Date | null;
        completedAt: Date | null;
        serverId: string;
        agentId: string | null;
        playbook: string;
        parameters: Prisma.JsonValue;
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
            summaryJson: Prisma.JsonValue;
            createdAt: Date;
            rawLog: string | null;
            storageMetricsJson: Prisma.JsonValue;
            memoryMetricsJson: Prisma.JsonValue;
            securityFindingsJson: Prisma.JsonValue;
        } | null;
        id: string;
        status: import(".prisma/client").$Enums.ServerScanStatus;
        startedAt: Date | null;
        completedAt: Date | null;
        serverId: string;
        agentId: string | null;
        playbook: string;
        parameters: Prisma.JsonValue;
        queuedAt: Date;
        failureReason: string | null;
        creditsCharged: number | null;
        agent: {
            id: string;
            status: import(".prisma/client").$Enums.ServerAgentStatus;
            lastSeenAt: Date | null;
        } | null;
    }[]>;
    getNextQueuedScan(agent: AgentSessionContext): Promise<{
        id: string;
        status: import(".prisma/client").$Enums.ServerScanStatus;
        startedAt: Date | null;
        serverId: string;
        playbook: string;
        parameters: Prisma.JsonValue;
        queuedAt: Date;
    } | null>;
    submitScanReport(agent: AgentSessionContext, scanId: string, dto: ReportServerScanDto): Promise<{
        id: string;
        status: "COMPLETED" | "FAILED";
        completedAt: Date;
    }>;
    ingestTelemetry(agent: AgentSessionContext, dto: TelemetryPayloadDto): Promise<{
        id: string;
        serverId: string;
        agentId: string | null;
        creditsCharged: number | null;
        cpuPercent: number | null;
        memoryPercent: number | null;
        diskPercent: number | null;
        collectedAt: Date;
    }>;
    private assertScanningAllowed;
}
//# sourceMappingURL=server-scan.service.d.ts.map