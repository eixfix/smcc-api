import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import type { Request } from 'express';
import type { AuthenticatedUser } from '../../common/types/auth-user';
import { PrismaService } from '../../prisma/prisma.service';
import { ServerService } from './server.service';
export declare class ServerAgentInstallController {
    private readonly configService;
    private readonly jwtService;
    private readonly prisma;
    private readonly serverService;
    constructor(configService: ConfigService, jwtService: JwtService, prisma: PrismaService, serverService: ServerService);
    createInstallLink(serverId: string, user: AuthenticatedUser): Promise<{
        installUrl: string;
        command: string;
        expiresInMinutes: number;
        nonce: string;
    }>;
    getInstallScript(token: string, request: Request): Promise<string>;
    private buildAgentSource;
}
//# sourceMappingURL=server-agent-install.controller.d.ts.map