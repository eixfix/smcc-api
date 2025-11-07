import { CanActivate, ExecutionContext } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
export interface AgentSessionPayload {
    sub: string;
    serverId: string;
    organizationId: string;
    type: 'agent-session';
    exp?: number;
    iat?: number;
}
export interface AgentSessionContext {
    agentId: string;
    serverId: string;
    organizationId: string;
}
export declare class AgentSessionGuard implements CanActivate {
    private readonly jwtService;
    private readonly configService;
    constructor(jwtService: JwtService, configService: ConfigService);
    canActivate(context: ExecutionContext): Promise<boolean>;
}
//# sourceMappingURL=agent-session.guard.d.ts.map