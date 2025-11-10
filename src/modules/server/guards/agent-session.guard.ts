import {
  BadRequestException,
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import type { Request } from 'express';
import { createDecipheriv } from 'node:crypto';

import { PrismaService } from '../../../prisma/prisma.service';
import { extractClientIp, normalizeIp } from '../../../common/utils/ip.utils';

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

interface AgentEnvelopeState {
  version: 'v1';
  key: Buffer;
}

type AgentAwareRequest = Request & {
  agent?: AgentSessionContext;
  agentEnvelope?: AgentEnvelopeState | null;
};

@Injectable()
export class AgentSessionGuard implements CanActivate {
  constructor(
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    private readonly prisma: PrismaService
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

      const clientIp = extractClientIp(request);
      await this.assertAllowedIp(payload.sub, payload.serverId, clientIp);

      const envelopeHeader = request.headers['x-agent-envelope'];
      const wantsEnvelope =
        typeof envelopeHeader === 'string' && envelopeHeader.toLowerCase() === 'v1';

      if (!wantsEnvelope) {
        throw new UnauthorizedException('Agent payloads must be encrypted.');
      }

      if (!payload.envelope || payload.envelopeVersion !== 'v1') {
        throw new UnauthorizedException('Agent session missing envelope key.');
      }

      const envelopeKey = Buffer.from(payload.envelope, 'base64');
      request.agentEnvelope = { version: 'v1', key: envelopeKey };

      if (request.body && Object.keys(request.body).length > 0) {
        request.body = this.decryptEnvelopePayload(envelopeKey, request.body);
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

  private async assertAllowedIp(
    agentId: string,
    serverId: string,
    clientIp: string | null
  ): Promise<void> {
    const agent = await this.prisma.serverAgent.findUnique({
      where: { id: agentId },
      select: {
        serverId: true,
        server: {
          select: {
            allowedIp: true
          }
        }
      }
    });

    if (!agent || agent.serverId !== serverId) {
      throw new UnauthorizedException('Agent session is no longer valid.');
    }

    const allowedIp = normalizeIp(agent.server.allowedIp);
    if (!allowedIp) {
      return;
    }

    const normalizedClientIp = normalizeIp(clientIp);
    if (!normalizedClientIp || normalizedClientIp !== allowedIp) {
      throw new UnauthorizedException('Agent IP is not authorized for this server.');
    }
  }

  private decryptEnvelopePayload(key: Buffer, payload: any): unknown {
    if (
      !payload ||
      typeof payload.ciphertext !== 'string' ||
      typeof payload.iv !== 'string' ||
      typeof payload.tag !== 'string'
    ) {
      throw new BadRequestException('Malformed encrypted payload.');
    }

    try {
      const decipher = createDecipheriv(
        'aes-256-gcm',
        key,
        Buffer.from(payload.iv, 'base64')
      );
      decipher.setAuthTag(Buffer.from(payload.tag, 'base64'));
      const plaintext = Buffer.concat([
        decipher.update(Buffer.from(payload.ciphertext, 'base64')),
        decipher.final()
      ]).toString('utf8');

      return plaintext.length > 0 ? JSON.parse(plaintext) : {};
    } catch (error) {
      throw new BadRequestException('Unable to decrypt agent payload.');
    }
  }
}
