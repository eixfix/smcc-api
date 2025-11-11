import {
  ForbiddenException,
  Injectable,
  InternalServerErrorException,
  UnauthorizedException
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { ServerAgentStatus } from '@prisma/client';
import * as bcrypt from 'bcryptjs';
import { createHmac, randomBytes } from 'crypto';

import { PrismaService } from '../../prisma/prisma.service';
import type { AuthenticatedUser } from '../../common/types/auth-user';
import { normalizeIp } from '../../common/utils/ip.utils';
import type { AgentSessionContext } from './guards/agent-session.guard';
import { ServerService } from './server.service';
import { AgentAuthDto } from './dto/agent-auth.dto';
import { CreateServerAgentDto } from './dto/create-server-agent.dto';
import {
  CREDIT_COST_SERVER_SCAN,
  CREDIT_COST_SERVER_TELEMETRY
} from '../../common/constants/credit-costs';

const SECRET_TOKEN_BYTE_LENGTH = 32;
const AGENT_SESSION_TTL_SECONDS = 15 * 60;
const DEFAULT_POLL_INTERVAL_SECONDS = 30;
const DEFAULT_TELEMETRY_INTERVAL_MINUTES = 30;
const DEFAULT_UPDATE_INTERVAL_MINUTES = 60;
const DEFAULT_CONFIG_REFRESH_MINUTES = 360;

@Injectable()
export class ServerAgentService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly serverService: ServerService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService
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

    const capabilities = Array.isArray(dto.capabilities)
      ? dto.capabilities.filter((flag) => typeof flag === 'string')
      : [];
    const capabilitySet = new Set(capabilities);

    if (!capabilitySet.has('envelope_v1')) {
      throw new UnauthorizedException('Agents must support envelope_v1.');
    }

    if (!capabilitySet.has('config_v1') || !capabilitySet.has('update_v1')) {
      throw new UnauthorizedException(
        'Agents must advertise config_v1 and update_v1 capabilities.'
      );
    }

    const envelopeKey = randomBytes(32);

    const sessionToken = await this.jwtService.signAsync({
      sub: agent.id,
      serverId: agent.serverId,
      organizationId: agent.server.organizationId,
      type: 'agent-session',
      envelope: envelopeKey.toString('base64'),
      envelopeVersion: 'v1',
      capabilities: Array.from(capabilitySet)
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

  getRemoteConfig(agent: AgentSessionContext) {
    const issuedAt = new Date().toISOString();
    const version =
      this.configService.get<string>('AGENT_CONFIG_VERSION') ?? '1.0.0';

    const payload = {
      version,
      issuedAt,
      serverId: agent.serverId,
      settings: {
        apiUrl: this.getApiUrl(),
        pollIntervalSeconds: this.getNumericEnv(
          'AGENT_CONFIG_POLL_INTERVAL_SECONDS',
          DEFAULT_POLL_INTERVAL_SECONDS
        ),
        telemetryIntervalMinutes: this.getNumericEnv(
          'AGENT_CONFIG_TELEMETRY_INTERVAL_MINUTES',
          DEFAULT_TELEMETRY_INTERVAL_MINUTES
        ),
        updateIntervalMinutes: this.getNumericEnv(
          'AGENT_CONFIG_UPDATE_INTERVAL_MINUTES',
          DEFAULT_UPDATE_INTERVAL_MINUTES
        ),
        refreshIntervalMinutes: this.getNumericEnv(
          'AGENT_CONFIG_REFRESH_INTERVAL_MINUTES',
          DEFAULT_CONFIG_REFRESH_MINUTES
        ),
        featureFlags: this.getFeatureFlags(),
        credits: {
          scan: CREDIT_COST_SERVER_SCAN,
          telemetry: CREDIT_COST_SERVER_TELEMETRY
        }
      }
    };

    return {
      ...payload,
      signature: this.signPayload(payload, true)
    };
  }

  getUpdateManifest(agent: AgentSessionContext, currentVersion?: string) {
    const version =
      this.configService.get<string>('AGENT_UPDATE_VERSION') ??
      this.configService.get<string>('AGENT_SCRIPT_VERSION') ??
      '1.0.0';
    const issuedAt = new Date().toISOString();
    const downloadUrl =
      this.configService.get<string>('AGENT_UPDATE_DOWNLOAD_URL') ?? null;
    const checksum =
      this.configService.get<string>('AGENT_UPDATE_CHECKSUM') ?? null;
    const inlineSource =
      this.configService.get<string>('AGENT_UPDATE_EMBEDDED_SOURCE_B64') ?? null;

    const manifest = {
      version,
      channel: this.configService.get<string>('AGENT_UPDATE_CHANNEL') ?? 'stable',
      issuedAt,
      serverId: agent.serverId,
      minConfigVersion:
        this.configService.get<string>('AGENT_CONFIG_VERSION') ?? '1.0.0',
      downloadUrl,
      checksum: checksum
        ? {
            algorithm: 'sha256',
            value: checksum
          }
        : null,
      inlineSource: inlineSource
        ? {
          encoding: 'base64' as const,
          data: inlineSource
        }
        : null,
      restartRequired: true,
      currentVersion: currentVersion ?? null
    };

    return {
      ...manifest,
      signature: this.signPayload(manifest, false)
    };
  }

  private getApiUrl(): string {
    const url = this.configService.get<string>('API_PUBLIC_URL') ?? '';
    return url.replace(/\/$/, '');
  }

  private getNumericEnv(key: string, fallback: number): number {
    const raw = this.configService.get<string>(key);
    const parsed = raw !== undefined ? Number(raw) : Number.NaN;
    return Number.isFinite(parsed) ? parsed : fallback;
  }

  private getFeatureFlags(): Record<string, boolean> {
    const rawFlags = this.configService.get<string>('AGENT_FEATURE_FLAGS_JSON');
    if (!rawFlags) {
      return {};
    }

    try {
      const parsed = JSON.parse(rawFlags);
      if (parsed && typeof parsed === 'object') {
        return Object.entries(parsed).reduce<Record<string, boolean>>(
          (acc, [key, value]) => {
            acc[key] = Boolean(value);
            return acc;
          },
          {}
        );
      }
    } catch {
      return {};
    }

    return {};
  }

  private signPayload(payload: unknown, isConfig: boolean): string {
    const key = isConfig ? this.getConfigSignatureKey() : this.getUpdateSignatureKey();
    try {
      return createHmac('sha256', key)
        .update(JSON.stringify(payload))
        .digest('base64');
    } catch (error) {
      throw new InternalServerErrorException('Unable to sign agent payload.');
    }
  }

  private getConfigSignatureKey(): Buffer {
    const raw =
      this.configService.get<string>('AGENT_CONFIG_SIGNATURE_KEY') ??
      this.configService.get<string>('AGENT_PAYLOAD_KEY');
    if (!raw) {
      throw new InternalServerErrorException(
        'AGENT_CONFIG_SIGNATURE_KEY is not configured.'
      );
    }
    return this.toKeyBuffer(raw);
  }

  private getUpdateSignatureKey(): Buffer {
    const raw =
      this.configService.get<string>('AGENT_UPDATE_SIGNATURE_KEY') ??
      this.configService.get<string>('AGENT_CONFIG_SIGNATURE_KEY') ??
      this.configService.get<string>('AGENT_PAYLOAD_KEY');
    if (!raw) {
      throw new InternalServerErrorException(
        'AGENT_UPDATE_SIGNATURE_KEY is not configured.'
      );
    }
    return this.toKeyBuffer(raw);
  }

  private toKeyBuffer(value: string): Buffer {
    try {
      return Buffer.from(value, /^[A-Za-z0-9+/=]+$/.test(value) ? 'base64' : 'utf8');
    } catch {
      return Buffer.from(value, 'utf8');
    }
  }
}
