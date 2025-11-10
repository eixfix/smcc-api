import type { Request } from 'express';
import type { AuthenticatedUser } from '../../common/types/auth-user';
import { AgentAuthDto } from './dto/agent-auth.dto';
import { CreateServerAgentDto } from './dto/create-server-agent.dto';
import { ServerAgentService } from './server-agent.service';
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
}
//# sourceMappingURL=server-agent.controller.d.ts.map