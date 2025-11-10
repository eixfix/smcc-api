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
  }
} as const;

const SERVER_DETAIL_SELECT = {
  ...SERVER_SUMMARY_SELECT,
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
      const accessibleOrganizationIds = await this.listUserOrganizationIds(user.userId);

      if (organizationId) {
        await this.ensureOrganizationReadAccess(organizationId, user);
        where.organizationId = organizationId;
      } else {
        if (accessibleOrganizationIds.length === 0) {
          return [];
        }

        where.organizationId = {
          in: accessibleOrganizationIds
        };
      }
    }

    return this.prisma.server.findMany({
      where,
      orderBy: { createdAt: 'desc' },
      select: SERVER_SUMMARY_SELECT
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

    return server;
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

  private async listUserOrganizationIds(userId: string): Promise<string[]> {
    const memberships = await this.prisma.organizationMember.findMany({
      where: { userId },
      select: { organizationId: true }
    });

    return memberships.map((membership) => membership.organizationId);
  }
}
