import {
  ForbiddenException,
  Injectable,
  NotFoundException
} from '@nestjs/common';
import { Prisma, ServerScanStatus } from '@prisma/client';

import {
  CREDIT_COST_SERVER_SCAN,
  CREDIT_COST_SERVER_TELEMETRY
} from '../../common/constants/credit-costs';
import type { AuthenticatedUser } from '../../common/types/auth-user';
import { PrismaService } from '../../prisma/prisma.service';
import { OrganizationCreditService } from '../organization/organization-credit.service';
import type { AgentSessionContext } from './guards/agent-session.guard';
import { QueueServerScanDto } from './dto/queue-server-scan.dto';
import { ReportServerScanDto } from './dto/report-server-scan.dto';
import { TelemetryPayloadDto } from './dto/telemetry-payload.dto';
import { ServerAgentService } from './server-agent.service';
import { ServerService } from './server.service';

const SCAN_WITH_RESULT_SELECT = {
  id: true,
  serverId: true,
  agentId: true,
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
      status: true,
      lastSeenAt: true
    }
  },
  result: {
    select: {
      summaryJson: true,
      rawLog: true,
      storageMetricsJson: true,
      memoryMetricsJson: true,
      securityFindingsJson: true,
      createdAt: true
    }
  }
} as const;

@Injectable()
export class ServerScanService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly creditService: OrganizationCreditService,
    private readonly serverService: ServerService,
    private readonly serverAgentService: ServerAgentService
  ) {}

  async queueScan(serverId: string, dto: QueueServerScanDto, user: AuthenticatedUser) {
    const server = await this.prisma.server.findUnique({
      where: { id: serverId },
      select: {
        id: true,
        organizationId: true,
        isSuspended: true,
        organization: {
          select: {
            id: true,
            scanSuspendedAt: true
          }
        }
      }
    });

    if (!server) {
      throw new NotFoundException('Server not found.');
    }

    await this.serverService.ensureOrganizationOwnerAccess(server.organizationId, user);

    this.assertScanningAllowed(server.isSuspended, server.organization.scanSuspendedAt);

    return this.prisma.$transaction(async (tx) => {
      await this.creditService.debitForServerScan(server.organizationId, tx);

      return tx.serverScan.create({
        data: {
          serverId,
          playbook: dto.playbook,
          parameters: dto.parameters
            ? (dto.parameters as Prisma.InputJsonValue)
            : undefined,
          status: ServerScanStatus.QUEUED,
          creditsCharged: CREDIT_COST_SERVER_SCAN
        },
        select: SCAN_WITH_RESULT_SELECT
      });
    });
  }

  async listScans(serverId: string, user: AuthenticatedUser) {
    await this.serverService.ensureServerOwnerAccess(serverId, user);

    return this.prisma.serverScan.findMany({
      where: { serverId },
      orderBy: { queuedAt: 'desc' },
      select: SCAN_WITH_RESULT_SELECT
    });
  }

  async getNextQueuedScan(agent: AgentSessionContext) {
    const server = await this.prisma.server.findUnique({
      where: { id: agent.serverId },
      select: {
        id: true,
        isSuspended: true,
        organization: {
          select: {
            id: true,
            scanSuspendedAt: true
          }
        }
      }
    });

    if (!server) {
      throw new NotFoundException('Server not found.');
    }

    this.assertScanningAllowed(server.isSuspended, server.organization.scanSuspendedAt);

    const job = await this.prisma.$transaction(async (tx) => {
      const pending = await tx.serverScan.findFirst({
        where: {
          serverId: agent.serverId,
          status: ServerScanStatus.QUEUED
        },
        orderBy: { queuedAt: 'asc' },
        select: {
          id: true,
          playbook: true,
          parameters: true
        }
      });

      if (!pending) {
        return null;
      }

      const now = new Date();

      const updated = await tx.serverScan.updateMany({
        where: {
          id: pending.id,
          status: ServerScanStatus.QUEUED
        },
        data: {
          status: ServerScanStatus.RUNNING,
          startedAt: now,
          agentId: agent.agentId
        }
      });

      if (updated.count === 0) {
        return null;
      }

      return tx.serverScan.findUnique({
        where: { id: pending.id },
        select: {
          id: true,
          playbook: true,
          parameters: true,
          serverId: true,
          status: true,
          queuedAt: true,
          startedAt: true
        }
      });
    });

    await this.serverAgentService.touchAgentHeartbeat(agent);

    return job;
  }

  async submitScanReport(
    agent: AgentSessionContext,
    scanId: string,
    dto: ReportServerScanDto
  ) {
    if (
      dto.status !== ServerScanStatus.COMPLETED &&
      dto.status !== ServerScanStatus.FAILED
    ) {
      throw new ForbiddenException('Invalid scan status update.');
    }

    const scan = await this.prisma.serverScan.findUnique({
      where: { id: scanId },
      select: {
        id: true,
        serverId: true,
        agentId: true,
        status: true
      }
    });

    if (!scan || scan.serverId !== agent.serverId) {
      throw new NotFoundException('Scan not found for this server.');
    }

    if (
      scan.status === ServerScanStatus.COMPLETED ||
      scan.status === ServerScanStatus.FAILED ||
      scan.status === ServerScanStatus.TIMED_OUT
    ) {
      throw new ForbiddenException('Scan has already been finalized.');
    }

    if (scan.agentId && scan.agentId !== agent.agentId) {
      throw new ForbiddenException('Scan is assigned to a different agent.');
    }

    const now = new Date();

    await this.prisma.$transaction(async (tx) => {
      await tx.serverScan.update({
        where: { id: scanId },
        data: {
          status: dto.status,
          completedAt: now,
          failureReason: dto.status === ServerScanStatus.FAILED ? dto.failureReason ?? 'Unknown failure' : null,
          agentId: agent.agentId
        }
      });

      await tx.serverScanResult.upsert({
        where: { scanId },
        create: {
          scanId,
          summaryJson: dto.summary
            ? (dto.summary as Prisma.InputJsonValue)
            : undefined,
          rawLog: dto.rawLog,
          storageMetricsJson: dto.storageMetrics
            ? (dto.storageMetrics as Prisma.InputJsonValue)
            : undefined,
          memoryMetricsJson: dto.memoryMetrics
            ? (dto.memoryMetrics as Prisma.InputJsonValue)
            : undefined,
          securityFindingsJson: dto.securityFindings
            ? (dto.securityFindings as Prisma.InputJsonValue)
            : undefined
        },
        update: {
          summaryJson: dto.summary
            ? (dto.summary as Prisma.InputJsonValue)
            : undefined,
          rawLog: dto.rawLog,
          storageMetricsJson: dto.storageMetrics
            ? (dto.storageMetrics as Prisma.InputJsonValue)
            : undefined,
          memoryMetricsJson: dto.memoryMetrics
            ? (dto.memoryMetrics as Prisma.InputJsonValue)
            : undefined,
          securityFindingsJson: dto.securityFindings
            ? (dto.securityFindings as Prisma.InputJsonValue)
            : undefined,
          createdAt: now
        }
      });
    });

    await this.serverAgentService.touchAgentHeartbeat(agent);

    return {
      id: scanId,
      status: dto.status,
      completedAt: now
    };
  }

  async ingestTelemetry(agent: AgentSessionContext, dto: TelemetryPayloadDto) {
    const server = await this.prisma.server.findUnique({
      where: { id: agent.serverId },
      select: {
        id: true,
        organizationId: true,
        isSuspended: true,
        organization: {
          select: {
            id: true,
            scanSuspendedAt: true
          }
        }
      }
    });

    if (!server) {
      throw new NotFoundException('Server not found.');
    }

    this.assertScanningAllowed(server.isSuspended, server.organization.scanSuspendedAt);

    const record = await this.prisma.$transaction(async (tx) => {
      await this.creditService.debitForTelemetry(server.organizationId, tx);

      const rawPayload: Record<string, unknown> = {
        ...(dto.raw ?? {})
      };

      if (dto.agentVersion) {
        rawPayload.agentVersion = dto.agentVersion;
      }

      if (dto.configVersion) {
        rawPayload.configVersion = dto.configVersion;
      }

      if (dto.updateStatus) {
        rawPayload.updateStatus = dto.updateStatus;
      }

      if (dto.lastUpdateCheckAt) {
        rawPayload.lastUpdateCheckAt = dto.lastUpdateCheckAt;
      }

      const hasRawPayload = Object.keys(rawPayload).length > 0;

      return tx.serverTelemetry.create({
        data: {
          serverId: agent.serverId,
          agentId: agent.agentId,
          cpuPercent: dto.cpuPercent ?? null,
          memoryPercent: dto.memoryPercent ?? null,
          diskPercent: dto.diskPercent ?? null,
          rawJson: hasRawPayload ? (rawPayload as Prisma.InputJsonValue) : undefined,
          creditsCharged: CREDIT_COST_SERVER_TELEMETRY
        },
        select: {
          id: true,
          serverId: true,
          agentId: true,
          cpuPercent: true,
          memoryPercent: true,
          diskPercent: true,
          collectedAt: true,
          creditsCharged: true
        }
      });
    });

    await this.serverAgentService.touchAgentHeartbeat(agent);

    return record;
  }

  private assertScanningAllowed(serverSuspended: boolean, scanSuspendedAt: Date | null) {
    if (serverSuspended) {
      throw new ForbiddenException('Server scanning is suspended.');
    }

    if (scanSuspendedAt) {
      throw new ForbiddenException('Organization scanning is suspended.');
    }
  }
}
