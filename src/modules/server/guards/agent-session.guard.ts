import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import type { Request } from 'express';

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

type AgentAwareRequest = Request & { agent?: AgentSessionContext };

@Injectable()
export class AgentSessionGuard implements CanActivate {
  constructor(
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<AgentAwareRequest>();
    const authorization = request.headers.authorization ?? '';

    if (!authorization || typeof authorization !== 'string') {
      throw new UnauthorizedException('Missing agent session token.');
    }

    const [scheme, token] = authorization.split(' ');

    if (!token || scheme.toLowerCase() !== 'bearer') {
      throw new UnauthorizedException('Invalid agent authorization header.');
    }

    try {
      const secret = this.configService.get<string>('JWT_SECRET');
      const payload = await this.jwtService.verifyAsync<AgentSessionPayload>(token, {
        secret
      });

      if (payload.type !== 'agent-session') {
        throw new UnauthorizedException('Invalid agent session token type.');
      }

      request.agent = {
        agentId: payload.sub,
        serverId: payload.serverId,
        organizationId: payload.organizationId
      };

      return true;
    } catch (error) {
      throw new UnauthorizedException('Invalid or expired agent session token.');
    }
  }
}
