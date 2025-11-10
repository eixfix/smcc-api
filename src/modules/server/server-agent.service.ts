import {
  ForbiddenException,
  Injectable,
  UnauthorizedException
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ServerAgentStatus } from '@prisma/client';
import * as bcrypt from 'bcryptjs';
import { randomBytes } from 'crypto';

import { PrismaService } from '../../prisma/prisma.service';
import type { AuthenticatedUser } from '../../common/types/auth-user';
import { normalizeIp } from '../../common/utils/ip.utils';
import type { AgentSessionContext } from './guards/agent-session.guard';
import { ServerService } from './server.service';
import { AgentAuthDto } from './dto/agent-auth.dto';
import { CreateServerAgentDto } from './dto/create-server-agent.dto';

const SECRET_TOKEN_BYTE_LENGTH = 32;
const AGENT_SESSION_TTL_SECONDS = 15 * 60;

@Injectable()
export class ServerAgentService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly serverService: ServerService,
    private readonly jwtService: JwtService
  ) {}

  async mintAgentToken(
    serverId: string,
    dto: CreateServerAgentDto,
    user: AuthenticatedUser
  ) {
    await this.serverService.ensureServerOwnerAccess(serverId, user);

    const accessKey = this.generateAccessKey();
    const secretToken = randomBytes(SECRET_TOKEN_BYTE_LENGTH).toString('hex');
    const hashedSecret = await bcrypt.hash(secretToken, 12);

    const agent = await this.prisma.$transaction(async (tx) => {
      await tx.serverAgent.updateMany({
        where: {
          serverId,
          status: ServerAgentStatus.ACTIVE
        },
        data: {
          status: ServerAgentStatus.REVOKED
        }
      });

      return tx.serverAgent.create({
        data: {
          serverId,
          accessKey,
          hashedSecret,
          issuedById: user.userId,
          expiresAt: dto.expiresAt ? new Date(dto.expiresAt) : null
        },
        select: {
          id: true,
          serverId: true,
          issuedAt: true,
          expiresAt: true,
          status: true,
          accessKey: true
        }
      });
    });

    return {
      agent,
      credentials: {
        accessKey,
        secret: secretToken
      }
    };
  }

  async revokeAgent(agentId: string, user: AuthenticatedUser) {
    const agent = await this.prisma.serverAgent.findUnique({
      where: { id: agentId },
      select: {
        id: true,
        status: true,
        server: {
          select: {
            id: true,
            organizationId: true
          }
        }
      }
    });

    if (!agent) {
      throw new ForbiddenException('Agent not found or access denied.');
    }

    await this.serverService.ensureOrganizationOwnerAccess(agent.server.organizationId, user);

    return this.prisma.serverAgent.update({
      where: { id: agentId },
      data: {
        status: ServerAgentStatus.REVOKED
      },
      select: {
        id: true,
        status: true,
        lastSeenAt: true
      }
    });
  }

  async authenticateAgent(dto: AgentAuthDto, clientIp: string | null) {
    const agent = await this.prisma.serverAgent.findFirst({
      where: {
        serverId: dto.serverId,
        accessKey: dto.accessKey
      },
      select: {
        id: true,
        hashedSecret: true,
        accessKey: true,
        expiresAt: true,
        status: true,
        serverId: true,
        server: {
          select: {
            id: true,
            name: true,
            allowedIp: true,
            isSuspended: true,
            organizationId: true,
            organization: {
              select: {
                id: true,
                name: true,
                credits: true,
                scanSuspendedAt: true
              }
            }
          }
        }
      }
    });

    if (!agent) {
      throw new UnauthorizedException('Invalid agent credentials.');
    }

    if (agent.status !== ServerAgentStatus.ACTIVE) {
      throw new UnauthorizedException('Agent token is no longer active.');
    }

    if (agent.expiresAt && agent.expiresAt.getTime() < Date.now()) {
      await this.prisma.serverAgent.update({
        where: { id: agent.id },
        data: { status: ServerAgentStatus.EXPIRED }
      });
      throw new UnauthorizedException('Agent token has expired.');
    }

    const normalizedClientIp = normalizeIp(clientIp);
    const allowedIp = normalizeIp(agent.server.allowedIp);

    if (allowedIp && normalizedClientIp !== allowedIp) {
      throw new UnauthorizedException('Agent IP is not authorized for this server.');
    }

    if (agent.server.isSuspended) {
      throw new ForbiddenException('Server scanning is suspended for this host.');
    }

    if (agent.server.organization.scanSuspendedAt) {
      throw new ForbiddenException('Organization scanning is currently suspended.');
    }

    const isValid = await bcrypt.compare(dto.secret, agent.hashedSecret);

    if (!isValid) {
      throw new UnauthorizedException('Invalid agent credentials.');
    }

    const wantsEnvelope = dto.capabilities?.includes('envelope_v1');

    if (!wantsEnvelope) {
      throw new UnauthorizedException('Agents must support envelope_v1.');
    }

    const envelopeKey = randomBytes(32);

    const sessionToken = await this.jwtService.signAsync({
      sub: agent.id,
      serverId: agent.serverId,
      organizationId: agent.server.organizationId,
      type: 'agent-session',
      envelope: envelopeKey.toString('base64'),
      envelopeVersion: 'v1'
    });

    const now = new Date();

    await this.prisma.serverAgent.update({
      where: { id: agent.id },
      data: {
        lastSeenAt: now
      }
    });

    return {
      sessionToken,
      expiresInSeconds: AGENT_SESSION_TTL_SECONDS,
      envelope: {
        version: 'v1',
        key: envelopeKey.toString('base64')
      },
      agent: {
        id: agent.id,
        serverId: agent.serverId,
        status: agent.status,
        lastSeenAt: now,
        expiresAt: agent.expiresAt
      },
      server: {
        id: agent.server.id,
        name: agent.server.name,
        isSuspended: agent.server.isSuspended
      },
      organization: {
        id: agent.server.organization.id,
        name: agent.server.organization.name,
        credits: agent.server.organization.credits,
        scanSuspendedAt: agent.server.organization.scanSuspendedAt
      }
    };
  }

  async touchAgentHeartbeat(agentContext: AgentSessionContext) {
    await this.prisma.serverAgent.update({
      where: { id: agentContext.agentId },
      data: {
        lastSeenAt: new Date()
      }
    });
  }

  private generateAccessKey(): string {
    const random = randomBytes(12).toString('base64url');
    return `agt_${random}`;
  }
}
