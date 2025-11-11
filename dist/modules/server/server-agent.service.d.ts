import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../../prisma/prisma.service';
import type { AuthenticatedUser } from '../../common/types/auth-user';
import type { AgentSessionContext } from './guards/agent-session.guard';
import { ServerService } from './server.service';
import { AgentAuthDto } from './dto/agent-auth.dto';
import { CreateServerAgentDto } from './dto/create-server-agent.dto';
export declare class ServerAgentService {
    private readonly prisma;
    private readonly serverService;
    private readonly jwtService;
    private readonly configService;
    constructor(prisma: PrismaService, serverService: ServerService, jwtService: JwtService, configService: ConfigService);
    mintAgentToken(serverId: string, dto: CreateServerAgentDto, user: AuthenticatedUser): Promise<{
        agent: {
            id: string;
            serverId: string;
            accessKey: string;
            issuedAt: Date;
            expiresAt: Date | null;
            status: import(".prisma/client").$Enums.ServerAgentStatus;
        };
        credentials: {
            accessKey: string;
            secret: string;
        };
    }>;
    revokeAgent(agentId: string, user: AuthenticatedUser): Promise<{
        id: string;
        lastSeenAt: Date | null;
        status: import(".prisma/client").$Enums.ServerAgentStatus;
    }>;
    authenticateAgent(dto: AgentAuthDto, clientIp: string | null): Promise<{
        sessionToken: string;
        expiresInSeconds: number;
        envelope: {
            version: string;
            key: string;
        };
        agent: {
            id: string;
            serverId: string;
            status: "ACTIVE";
            lastSeenAt: Date;
            expiresAt: Date | null;
        };
        server: {
            id: string;
            name: string;
            isSuspended: false;
        };
        organization: {
            id: string;
            name: string;
            credits: number;
            scanSuspendedAt: null;
        };
    }>;
    touchAgentHeartbeat(agentContext: AgentSessionContext): Promise<void>;
    private generateAccessKey;
    getRemoteConfig(agent: AgentSessionContext): {
        signature: string;
        version: string;
        issuedAt: string;
        serverId: string;
        settings: {
            apiUrl: string;
            pollIntervalSeconds: number;
            telemetryIntervalMinutes: number;
            updateIntervalMinutes: number;
            refreshIntervalMinutes: number;
            featureFlags: Record<string, boolean>;
            credits: {
                scan: number;
                telemetry: number;
            };
        };
    };
    getUpdateManifest(agent: AgentSessionContext, currentVersion?: string): {
        signature: string;
        version: string;
        channel: string;
        issuedAt: string;
        serverId: string;
        minConfigVersion: string;
        downloadUrl: string | null;
        checksum: {
            algorithm: string;
            value: string;
        } | null;
        inlineSource: {
            encoding: "base64";
            data: string;
        } | null;
        restartRequired: boolean;
        currentVersion: string | null;
    };
    private getApiUrl;
    private getNumericEnv;
    private getFeatureFlags;
    private signPayload;
    private getConfigSignatureKey;
    private getUpdateSignatureKey;
    private toKeyBuffer;
}
//# sourceMappingURL=server-agent.service.d.ts.map