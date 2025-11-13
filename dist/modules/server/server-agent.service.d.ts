import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../../prisma/prisma.service';
import type { AuthenticatedUser } from '../../common/types/auth-user';
import type { AgentSessionContext } from './guards/agent-session.guard';
import { ServerService } from './server.service';
import { AgentAuthDto } from './dto/agent-auth.dto';
import { CreateServerAgentDto } from './dto/create-server-agent.dto';
import { CreateAgentUpdateManifestDto } from './dto/create-agent-update-manifest.dto';
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
    publishUpdateManifest(dto: CreateAgentUpdateManifestDto, user: AuthenticatedUser): Promise<{
        id: string;
        version: string;
        channel: string;
        downloadUrl: string | null;
        hasInlineSource: boolean;
        checksum: {
            algorithm: string;
            value: string;
        } | null;
        restartRequired: boolean;
        minConfigVersion: string | null;
        notes: string | null;
        createdAt: string;
        createdBy: {
            id: string;
            email: string;
            name: string;
        } | null;
    }>;
    listUpdateManifests(user: AuthenticatedUser, limit?: number): Promise<{
        id: string;
        version: string;
        channel: string;
        downloadUrl: string | null;
        hasInlineSource: boolean;
        checksum: {
            algorithm: string;
            value: string;
        } | null;
        restartRequired: boolean;
        minConfigVersion: string | null;
        notes: string | null;
        createdAt: string;
        createdBy: {
            id: string;
            email: string;
            name: string;
        } | null;
    }[]>;
    getUpdateManifest(agent: AgentSessionContext, currentVersion?: string): Promise<{
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
    } | null>;
    private getApiUrl;
    private getDefaultConfigVersion;
    private buildLegacyUpdateManifest;
    private getNumericEnv;
    private buildManifestPayload;
    private mapManifestForAdmin;
    private getFeatureFlags;
    private signPayload;
    private getConfigSignatureKey;
    private getUpdateSignatureKey;
    private toKeyBuffer;
    private isRecord;
    private ensureAdministrator;
}
//# sourceMappingURL=server-agent.service.d.ts.map