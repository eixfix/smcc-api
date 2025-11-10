import { CanActivate, ExecutionContext } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../../../prisma/prisma.service';
export interface AgentSessionPayload {
    sub: string;
    serverId: string;
    organizationId: string;
    type: 'agent-session';
    envelope?: string;
    envelopeVersion?: 'v1';
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
    private readonly prisma;
    constructor(jwtService: JwtService, configService: ConfigService, prisma: PrismaService);
    canActivate(context: ExecutionContext): Promise<boolean>;
    private assertAllowedIp;
    private decryptEnvelopePayload;
}
//# sourceMappingURL=agent-session.guard.d.ts.map