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
    constructor(prisma: PrismaService, serverService: ServerService, jwtService: JwtService);
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
}
//# sourceMappingURL=server-agent.service.d.ts.map