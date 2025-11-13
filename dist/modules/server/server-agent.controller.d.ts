import type { Request } from 'express';
import type { AuthenticatedUser } from '../../common/types/auth-user';
import { AgentAuthDto } from './dto/agent-auth.dto';
import { CreateServerAgentDto } from './dto/create-server-agent.dto';
import { CreateAgentUpdateManifestDto } from './dto/create-agent-update-manifest.dto';
import type { AgentSessionContext } from './guards/agent-session.guard';
import { ServerAgentService } from './server-agent.service';
interface AgentCapabilityRequest extends Request {
    agentCapabilities?: string[];
}
export declare class ServerAgentController {
    private readonly serverAgentService;
    constructor(serverAgentService: ServerAgentService);
    createAgent(serverId: string, payload: CreateServerAgentDto, user: AuthenticatedUser): Promise<{
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
    authenticate(payload: AgentAuthDto, request: Request): Promise<{
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
    fetchConfig(request: AgentCapabilityRequest, agent: AgentSessionContext | undefined): {
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
    fetchUpdateManifest(request: AgentCapabilityRequest, agent: AgentSessionContext | undefined, currentVersion?: string): Promise<{
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
    publishUpdateManifest(payload: CreateAgentUpdateManifestDto, user: AuthenticatedUser): Promise<{
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
    listUpdateManifests(user: AuthenticatedUser, limit?: string): Promise<{
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
    private assertCapability;
}
export {};
//# sourceMappingURL=server-agent.controller.d.ts.map