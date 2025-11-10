import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  NotFoundException
} from '@nestjs/common';
import type { Prisma } from '@prisma/client';
import { Role } from '@prisma/client';

import { PrismaService } from '../../prisma/prisma.service';
import type { AuthenticatedUser } from '../../common/types/auth-user';
import { normalizeIp } from '../../common/utils/ip.utils';
import { CreateServerDto } from './dto/create-server.dto';
import { UpdateServerDto } from './dto/update-server.dto';

const TELEMETRY_SELECT = {
  id: true,
  collectedAt: true,
  cpuPercent: true,
  memoryPercent: true,
  diskPercent: true
} as const;

const SERVER_SUMMARY_SELECT = {
  id: true,
  name: true,
  hostname: true,
  allowedIp: true,
  description: true,
  isSuspended: true,
  createdAt: true,
  updatedAt: true,
  organization: {
    select: {
      id: true,
      name: true,
      credits: true,
      lastCreditedAt: true,
      lastDebitAt: true,
      scanSuspendedAt: true
    }
  },
  telemetry: {
    orderBy: { collectedAt: 'desc' },
    take: 1,
    select: TELEMETRY_SELECT
  }
} as const;

const SERVER_DETAIL_SELECT = {
  ...SERVER_SUMMARY_SELECT,
  telemetry: {
    orderBy: { collectedAt: 'desc' },
    take: 25,
    select: TELEMETRY_SELECT
  },
  agents: {
    orderBy: { issuedAt: 'desc' },
    select: {
      id: true,
      accessKey: true,
      issuedAt: true,
      expiresAt: true,
      lastSeenAt: true,
      status: true
    }
  },
  scans: {
    orderBy: { queuedAt: 'desc' },
    take: 10,
    select: {
      id: true,
      playbook: true,
      parameters: true,
      status: true,
      queuedAt: true,
      startedAt: true,
      completedAt: true,
      failureReason: true,
      creditsCharged: true,
      agent: {
        select: {
          id: true,
          status: true
        }
      }
    }
  }
} as const;

@Injectable()
export class ServerService {
  constructor(private readonly prisma: PrismaService) {}

  async create(payload: CreateServerDto, user: AuthenticatedUser) {
    await this.ensureOrganizationOwnerAccess(payload.organizationId, user);
    const allowedIp = normalizeIp(payload.allowedIp);

    if (!allowedIp) {
      throw new BadRequestException('A valid server IP address is required.');
    }

    return this.prisma.server.create({
      data: {
        organizationId: payload.organizationId,
        name: payload.name,
        hostname: payload.hostname,
        allowedIp,
        description: payload.description,
        createdById: user.userId
      },
      select: SERVER_DETAIL_SELECT
    });
  }

  async findAll(user: AuthenticatedUser, organizationId?: string) {
    const where: Prisma.ServerWhereInput = {};
    let membershipRoles: Map<string, Role> | undefined;

    if (user.role === Role.ADMINISTRATOR) {
      if (organizationId) {
        const exists = await this.prisma.organization.findUnique({
          where: { id: organizationId },
          select: { id: true }
        });

        if (!exists) {
          throw new NotFoundException('Organization not found.');
        }

        where.organizationId = organizationId;
      }
    } else {
      membershipRoles = await this.getUserMembershipRoleMap(user.userId);

      if (organizationId) {
        await this.ensureOrganizationReadAccess(organizationId, user);
        where.organizationId = organizationId;
      } else {
        const accessibleOrganizationIds = Array.from(membershipRoles.keys());

        if (accessibleOrganizationIds.length === 0) {
          return [];
        }

        where.organizationId = {
          in: accessibleOrganizationIds
        };
      }
    }

    const servers = await this.prisma.server.findMany({
      where,
      orderBy: { createdAt: 'desc' },
      select: SERVER_SUMMARY_SELECT
    });

    if (user.role === Role.ADMINISTRATOR) {
      return servers;
    }

    return servers.map((server) => {
      if (this.userCanViewTelemetry(user, server.organization.id, membershipRoles)) {
        return server;
      }

      return this.stripTelemetry(server);
    });
  }

  async findOne(id: string, user: AuthenticatedUser) {
    const server = await this.prisma.server.findUnique({
      where: { id },
      select: SERVER_DETAIL_SELECT
    });

    if (!server) {
      throw new NotFoundException('Server not found.');
    }

    await this.ensureOrganizationReadAccess(server.organization.id, user);

    if (user.role === Role.ADMINISTRATOR) {
      return server;
    }

    const membershipRole = await this.getUserOrganizationRole(server.organization.id, user.userId);

    if (membershipRole === Role.OWNER) {
      return server;
    }

    return this.stripTelemetry(server);
  }

  async update(id: string, payload: UpdateServerDto, user: AuthenticatedUser) {
    const summary = await this.prisma.server.findUnique({
      where: { id },
      select: { id: true, organizationId: true }
    });

    if (!summary) {
      throw new NotFoundException('Server not found.');
    }

    if (payload.isSuspended !== undefined) {
      await this.ensureOrganizationOwnerAccess(summary.organizationId, user);
    } else {
      await this.ensureOrganizationReadAccess(summary.organizationId, user);
    }

    const allowedIp =
      payload.allowedIp !== undefined ? normalizeIp(payload.allowedIp) : undefined;

    if (payload.allowedIp !== undefined && !allowedIp) {
      throw new BadRequestException('A valid server IP address is required.');
    }

    return this.prisma.server.update({
      where: { id },
      data: {
        name: payload.name,
        hostname: payload.hostname,
        description: payload.description,
        allowedIp,
        isSuspended:
          payload.isSuspended !== undefined ? payload.isSuspended : undefined
      },
      select: SERVER_DETAIL_SELECT
    });
  }

  async setSuspension(id: string, isSuspended: boolean, user: AuthenticatedUser) {
    const server = await this.prisma.server.findUnique({
      where: { id },
      select: { id: true, organizationId: true }
    });

    if (!server) {
      throw new NotFoundException('Server not found.');
    }

    await this.ensureOrganizationOwnerAccess(server.organizationId, user);

    return this.prisma.server.update({
      where: { id },
      data: {
        isSuspended
      },
      select: SERVER_DETAIL_SELECT
    });
  }

  async listTelemetry(serverId: string, user: AuthenticatedUser, limit?: number) {
    await this.ensureServerOwnerAccess(serverId, user);

    const take = Math.min(Math.max(limit ?? 25, 1), 100);

    return this.prisma.serverTelemetry.findMany({
      where: { serverId },
      orderBy: { collectedAt: 'desc' },
      take,
      select: TELEMETRY_SELECT
    });
  }

  async ensureServerOwnerAccess(
    serverId: string,
    user: AuthenticatedUser
  ): Promise<{
    id: string;
    organizationId: string;
  }> {
    const server = await this.prisma.server.findUnique({
      where: { id: serverId },
      select: { id: true, organizationId: true }
    });

    if (!server) {
      throw new NotFoundException('Server not found.');
    }

    await this.ensureOrganizationOwnerAccess(server.organizationId, user);
    return server;
  }

  private async ensureOrganizationReadAccess(
    organizationId: string,
    user: AuthenticatedUser
  ): Promise<void> {
    if (user.role === Role.ADMINISTRATOR) {
      const exists = await this.prisma.organization.findUnique({
        where: { id: organizationId },
        select: { id: true }
      });

      if (!exists) {
        throw new NotFoundException('Organization not found.');
      }

      return;
    }

    const membership = await this.prisma.organizationMember.findFirst({
      where: {
        organizationId,
        userId: user.userId
      },
      select: { id: true }
    });

    if (!membership) {
      throw new ForbiddenException('You do not have access to this organization.');
    }
  }

  async ensureOrganizationOwnerAccess(
    organizationId: string,
    user: AuthenticatedUser
  ): Promise<void> {
    if (user.role === Role.ADMINISTRATOR) {
      const exists = await this.prisma.organization.findUnique({
        where: { id: organizationId },
        select: { id: true }
      });

      if (!exists) {
        throw new NotFoundException('Organization not found.');
      }

      return;
    }

    const membership = await this.prisma.organizationMember.findFirst({
      where: {
        organizationId,
        userId: user.userId
      },
      select: { role: true }
    });

    if (!membership) {
      throw new ForbiddenException('You do not have access to this organization.');
    }

    if (membership.role !== Role.OWNER) {
      throw new ForbiddenException('Owner privileges are required for this action.');
    }
  }

  private userCanViewTelemetry(
    user: AuthenticatedUser,
    organizationId: string,
    membershipRoles?: Map<string, Role>
  ): boolean {
    if (user.role === Role.ADMINISTRATOR) {
      return true;
    }

    if (!membershipRoles) {
      return false;
    }

    return membershipRoles.get(organizationId) === Role.OWNER;
  }

  private stripTelemetry<T extends { telemetry: Array<unknown> }>(record: T): T {
    return {
      ...record,
      telemetry: [] as typeof record.telemetry
    };
  }

  private async getUserMembershipRoleMap(userId: string): Promise<Map<string, Role>> {
    const memberships = await this.prisma.organizationMember.findMany({
      where: { userId },
      select: { organizationId: true, role: true }
    });

    return new Map(memberships.map((membership) => [membership.organizationId, membership.role]));
  }

  private async getUserOrganizationRole(
    organizationId: string,
    userId: string
  ): Promise<Role | null> {
    const membership = await this.prisma.organizationMember.findFirst({
      where: {
        organizationId,
        userId
      },
      select: { role: true }
    });

    return membership?.role ?? null;
  }
}
