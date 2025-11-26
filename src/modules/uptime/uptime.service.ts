import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  Logger,
  NotFoundException,
  OnModuleDestroy,
  OnModuleInit
} from '@nestjs/common';
import type { Prisma } from '@prisma/client';
import {
  Role,
  UptimeProtocol,
  UptimeReason,
  UptimeSensitivity,
  UptimeState
} from '@prisma/client';
import * as dns from 'node:dns/promises';
import * as tls from 'node:tls';

import { PrismaService } from '../../prisma/prisma.service';
import type { AuthenticatedUser } from '../../common/types/auth-user';
import { CreateUptimeTargetDto } from './dto/create-uptime-target.dto';
import { TestWebhookDto } from './dto/test-webhook.dto';
import { UpdateUptimeTargetDto } from './dto/update-uptime-target.dto';
import {
  TargetNotificationContext,
  UptimeNotifierService
} from './uptime-notifier.service';

const TARGET_WITH_CONTEXT_INCLUDE = {
  organization: {
    select: {
      id: true,
      name: true,
      uptimeWebhookUrl: true
    }
  },
  project: {
    select: {
      id: true,
      name: true,
      uptimeWebhookUrl: true
    }
  },
  currentSnapshot: true
} as const satisfies Prisma.UptimeTargetInclude;

type TargetWithContext = Prisma.UptimeTargetGetPayload<{
  include: typeof TARGET_WITH_CONTEXT_INCLUDE;
}>;

interface ProbeResult {
  state: UptimeState;
  reason: UptimeReason;
  reasonDetail?: string | null;
  statusCode?: number | null;
  latencyMs?: number | null;
  tlsExpiresAt?: Date | null;
  resolvedAddress?: string | null;
  checkedAt: Date;
}

const DEFAULT_SCHEDULER_INTERVAL_MS = Number(
  process.env.UPTIME_SCHEDULER_INTERVAL_MS ?? 5 * 60 * 1000
);
const MIN_SCHEDULER_INTERVAL_MS = 1000;
const DEFAULT_DIGEST_INTERVAL_MS = Number(
  process.env.UPTIME_DIGEST_INTERVAL_MS ?? 4.8 * 60 * 60 * 1000
);

@Injectable()
export class UptimeService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(UptimeService.name);
  private scheduler: NodeJS.Timeout | null = null;
  private readonly digestTracker = new Map<string, number>();

  constructor(
    private readonly prisma: PrismaService,
    private readonly notifier: UptimeNotifierService
  ) {}

  async onModuleInit(): Promise<void> {
    if (process.env.UPTIME_SCHEDULER_ENABLED === 'false') {
      this.logger.log('Uptime scheduler disabled via env flag.');
      return;
    }

    this.scheduleNextRun(0);
  }

  async onModuleDestroy(): Promise<void> {
    if (this.scheduler) {
      clearTimeout(this.scheduler);
      this.scheduler = null;
    }
  }

  async listTargets(
    organizationId: string,
    user: AuthenticatedUser
  ): Promise<TargetWithContext[]> {
    await this.ensureOrganizationReadAccess(organizationId, user);

    return this.prisma.uptimeTarget.findMany({
      where: { organizationId },
      orderBy: { createdAt: 'desc' },
      include: TARGET_WITH_CONTEXT_INCLUDE
    });
  }

  async getTarget(
    organizationId: string,
    targetId: string,
    user: AuthenticatedUser
  ): Promise<TargetWithContext & { recentChecks: unknown[] }> {
    await this.ensureOrganizationReadAccess(organizationId, user);

    const target = await this.prisma.uptimeTarget.findFirst({
      where: {
        id: targetId,
        organizationId
      },
      include: {
        ...TARGET_WITH_CONTEXT_INCLUDE,
        checks: {
          orderBy: { checkedAt: 'desc' },
          take: 25
        }
      }
    });

    if (!target) {
      throw new NotFoundException('Uptime target not found.');
    }

    const { checks, ...rest } = target;
    return { ...rest, recentChecks: checks };
  }

  async listChecks(
    organizationId: string,
    targetId: string,
    user: AuthenticatedUser,
    limit?: number
  ) {
    await this.ensureOrganizationReadAccess(organizationId, user);
    await this.ensureTargetInOrganization(organizationId, targetId);

    const take = Math.min(Math.max(limit ?? 25, 1), 200);

    return this.prisma.uptimeCheck.findMany({
      where: { targetId },
      orderBy: { checkedAt: 'desc' },
      take
    });
  }

  async createTarget(
    organizationId: string,
    payload: CreateUptimeTargetDto,
    user: AuthenticatedUser
  ): Promise<TargetWithContext> {
    await this.ensureOrganizationOwnerAccess(organizationId, user);

    if (payload.projectId) {
      await this.ensureProjectInOrganization(payload.projectId, organizationId);
    }

    if (payload.serverId) {
      await this.ensureServerInOrganization(payload.serverId, organizationId);
    }

    const normalized = this.normalizeTargetUrl(payload.url, payload.protocol);

    return this.prisma.$transaction(async (tx) => {
      const target = await tx.uptimeTarget.create({
        data: {
          organizationId,
          projectId: payload.projectId,
          serverId: payload.serverId,
          label: payload.label,
          url: normalized.url,
          protocol: normalized.protocol,
          region: payload.region,
          sensitivity: payload.sensitivity ?? UptimeSensitivity.PRODUCTION,
          checkIntervalSeconds: payload.checkIntervalSeconds ?? 300,
          requestTimeoutMs: payload.requestTimeoutMs ?? 5000,
          expectedStatus: payload.expectedStatus,
          alertWebhookUrl: payload.alertWebhookUrl,
          isPaused: payload.isPaused ?? false
        }
      });

      const snapshot = await tx.uptimeStatusSnapshot.create({
        data: {
          targetId: target.id,
          state: UptimeState.UNKNOWN,
          reason: UptimeReason.UNKNOWN,
          since: new Date()
        }
      });

      return tx.uptimeTarget.update({
        where: { id: target.id },
        data: {
          currentSnapshotId: snapshot.id
        },
        include: TARGET_WITH_CONTEXT_INCLUDE
      });
    });
  }

  async updateTarget(
    organizationId: string,
    targetId: string,
    payload: UpdateUptimeTargetDto,
    user: AuthenticatedUser
  ): Promise<TargetWithContext> {
    await this.ensureOrganizationOwnerAccess(organizationId, user);
    const target = await this.ensureTargetInOrganization(organizationId, targetId);

    if (payload.projectId) {
      await this.ensureProjectInOrganization(payload.projectId, organizationId);
    }

    if (payload.serverId) {
      await this.ensureServerInOrganization(payload.serverId, organizationId);
    }

    const normalized = payload.url
      ? this.normalizeTargetUrl(payload.url, payload.protocol ?? target.protocol)
      : null;

    return this.prisma.uptimeTarget.update({
      where: { id: targetId },
      data: {
        projectId: payload.projectId,
        serverId: payload.serverId,
        label: payload.label,
        url: normalized?.url,
        protocol: normalized?.protocol,
        region: payload.region,
        sensitivity: payload.sensitivity,
        checkIntervalSeconds: payload.checkIntervalSeconds,
        requestTimeoutMs: payload.requestTimeoutMs,
        expectedStatus: payload.expectedStatus,
        alertWebhookUrl: payload.alertWebhookUrl,
        isPaused: payload.isPaused
      },
      include: TARGET_WITH_CONTEXT_INCLUDE
    });
  }

  async runCheckNow(
    organizationId: string,
    targetId: string,
    user: AuthenticatedUser
  ) {
    await this.ensureOrganizationReadAccess(organizationId, user);
    const target = await this.prisma.uptimeTarget.findFirst({
      where: { id: targetId, organizationId },
      include: TARGET_WITH_CONTEXT_INCLUDE
    });

    if (!target) {
      throw new NotFoundException('Uptime target not found.');
    }

    return this.runProbeForTarget(target);
  }

  async testWebhook(
    organizationId: string,
    targetId: string,
    payload: TestWebhookDto,
    user: AuthenticatedUser
  ) {
    await this.ensureOrganizationOwnerAccess(organizationId, user);

    const target = await this.prisma.uptimeTarget.findFirst({
      where: { id: targetId, organizationId },
      include: TARGET_WITH_CONTEXT_INCLUDE
    });

    if (!target) {
      throw new NotFoundException('Uptime target not found.');
    }

    const webhookUrl =
      payload.webhookUrl ??
      target.alertWebhookUrl ??
      target.project?.uptimeWebhookUrl ??
      target.organization.uptimeWebhookUrl;

    if (!webhookUrl) {
      throw new BadRequestException('No webhook URL configured for this target or organization.');
    }

    await this.notifier.sendTest(webhookUrl, target.label, {
      state: payload.state,
      reason: payload.reason,
      reasonDetail: payload.reasonDetail
    });

    return { ok: true };
  }

  async runScheduledChecks(): Promise<number> {
    const targets = await this.prisma.uptimeTarget.findMany({
      where: { isPaused: false },
      include: TARGET_WITH_CONTEXT_INCLUDE
    });

    const now = Date.now();
    let nextDelayMs = DEFAULT_SCHEDULER_INTERVAL_MS;

    if (targets.length > 0) {
      const nextDueMs = targets.reduce((min, target) => {
        const last = target.lastCheckedAt?.getTime() ?? 0;
        const dueAt = last + target.checkIntervalSeconds * 1000;
        const delta = Math.max(dueAt - now, 0);
        return Math.min(min, delta);
      }, Number.POSITIVE_INFINITY);

      if (Number.isFinite(nextDueMs)) {
        nextDelayMs = Math.max(MIN_SCHEDULER_INTERVAL_MS, nextDueMs);
      }
    }

    for (const target of targets) {
      if (
        target.lastCheckedAt &&
        now - target.lastCheckedAt.getTime() < target.checkIntervalSeconds * 1000
      ) {
        continue;
      }

      try {
        await this.runProbeForTarget(target);
      } catch (error) {
        this.logger.error(
          `Failed to run uptime check for ${target.url}: ${(error as Error).message}`
        );
      }
    }

    await this.maybeSendDigests();
    return nextDelayMs;
  }

  private async runProbeForTarget(target: TargetWithContext) {
    const probeResult = await this.performCheck(target);
    const previousSnapshot = target.currentSnapshot;

    const { check, snapshot, updatedTarget } = await this.persistProbeResult(
      target,
      probeResult
    );

    if (!previousSnapshot || previousSnapshot.state !== snapshot.state) {
      const previousDurationMs = previousSnapshot
        ? probeResult.checkedAt.getTime() - previousSnapshot.since.getTime()
        : 0;

      await this.notifier.sendStateChange(
        this.toNotificationTarget(updatedTarget),
        {
          state: snapshot.state,
          reason: snapshot.reason,
          reasonDetail: snapshot.reasonDetail,
          since: snapshot.since
        },
        {
          statusCode: check.statusCode,
          latencyMs: check.latencyMs,
          tlsExpiresAt: check.tlsExpiresAt,
          checkedAt: check.checkedAt
        },
        previousDurationMs
      );
    }

    return { target: updatedTarget, snapshot, check };
  }

  private async performCheck(target: TargetWithContext): Promise<ProbeResult> {
    const timeoutMs = target.requestTimeoutMs ?? 5000;
    const startedAt = Date.now();
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);
    const url = target.url;

    try {
      const response = await fetch(url, { method: 'GET', signal: controller.signal });
      const latencyMs = Date.now() - startedAt;
      const statusCode = response.status;
      const tlsExpiresAt = await this.resolveTlsExpiry(url);
      const resolvedAddress = await this.resolveAddress(url);

      const stateDetail = this.resolveStateFromResponse(
        statusCode,
        latencyMs,
        timeoutMs,
        target.expectedStatus,
        tlsExpiresAt
      );

      return {
        ...stateDetail,
        statusCode,
        latencyMs,
        tlsExpiresAt,
        resolvedAddress,
        checkedAt: new Date()
      };
    } catch (error) {
      const latencyMs = Date.now() - startedAt;
      return {
        ...this.mapErrorToState(error, timeoutMs),
        latencyMs,
        checkedAt: new Date()
      };
    } finally {
      clearTimeout(timeout);
    }
  }

  private resolveStateFromResponse(
    statusCode: number,
    latencyMs: number,
    timeoutMs: number,
    expectedStatus?: number | null,
    tlsExpiresAt?: Date | null
  ): { state: UptimeState; reason: UptimeReason; reasonDetail: string } {
    if (statusCode >= 500) {
      return {
        state: UptimeState.DOWN,
        reason: UptimeReason.STATUS_CODE,
        reasonDetail: `Received ${statusCode}`
      };
    }

    if (expectedStatus && statusCode !== expectedStatus) {
      return {
        state: UptimeState.DEGRADED,
        reason: UptimeReason.STATUS_CODE,
        reasonDetail: `Expected ${expectedStatus}, got ${statusCode}`
      };
    }

    if (statusCode >= 400) {
      return {
        state: UptimeState.DEGRADED,
        reason: UptimeReason.STATUS_CODE,
        reasonDetail: `Received ${statusCode}`
      };
    }

    const nearTimeout = latencyMs > timeoutMs * 0.8;

    if (nearTimeout) {
      return {
        state: UptimeState.DEGRADED,
        reason: UptimeReason.TIMEOUT,
        reasonDetail: `Slow response (${latencyMs} ms)`
      };
    }

    if (tlsExpiresAt) {
      const daysUntilExpiry = this.daysUntil(tlsExpiresAt);

      if (daysUntilExpiry <= 7) {
        return {
          state: UptimeState.DEGRADED,
          reason: UptimeReason.TLS,
          reasonDetail: `TLS expires in ${daysUntilExpiry} day(s)`
        };
      }
    }

    return {
      state: UptimeState.UP,
      reason: UptimeReason.STATUS_CODE,
      reasonDetail: 'Server online'
    };
  }

  private mapErrorToState(
    error: unknown,
    timeoutMs: number
  ): { state: UptimeState; reason: UptimeReason; reasonDetail: string } {
    const message = (error as Error).message ?? 'Unknown error';

    if ((error as { name?: string }).name === 'AbortError') {
      return {
        state: UptimeState.DOWN,
        reason: UptimeReason.TIMEOUT,
        reasonDetail: `Timed out after ${timeoutMs} ms`
      };
    }

    const code = (error as { code?: string })?.code ?? (error as { cause?: { code?: string } })?.cause?.code;

    if (code === 'ENOTFOUND') {
      return { state: UptimeState.DOWN, reason: UptimeReason.DNS, reasonDetail: 'DNS resolution failed' };
    }

    if (code === 'ECONNREFUSED' || code === 'ECONNRESET') {
      return { state: UptimeState.DOWN, reason: UptimeReason.NETWORK, reasonDetail: 'Connection refused/reset' };
    }

    if (message.toLowerCase().includes('tls')) {
      return { state: UptimeState.DEGRADED, reason: UptimeReason.TLS, reasonDetail: message };
    }

    return {
      state: UptimeState.DOWN,
      reason: UptimeReason.UNKNOWN,
      reasonDetail: message
    };
  }

  private async persistProbeResult(target: TargetWithContext, result: ProbeResult) {
    return this.prisma.$transaction(async (tx) => {
      const check = await tx.uptimeCheck.create({
        data: {
          targetId: target.id,
          state: result.state,
          reason: result.reason,
          reasonDetail: result.reasonDetail,
          statusCode: result.statusCode,
          latencyMs: result.latencyMs,
          tlsExpiresAt: result.tlsExpiresAt,
          region: target.region,
          resolvedAddress: result.resolvedAddress,
          checkedAt: result.checkedAt
        }
      });

      let snapshotId = target.currentSnapshotId ?? null;

      if (!target.currentSnapshot || target.currentSnapshot.state !== result.state || !target.currentSnapshotId) {
        const snapshot = await tx.uptimeStatusSnapshot.create({
          data: {
            targetId: target.id,
            state: result.state,
            reason: result.reason,
            reasonDetail: result.reasonDetail,
            since: result.checkedAt,
            lastCheckId: check.id
          }
        });

        snapshotId = snapshot.id;
      } else {
        await tx.uptimeStatusSnapshot.update({
          where: { id: target.currentSnapshotId },
          data: {
            reason: result.reason,
            reasonDetail: result.reasonDetail,
            lastCheckId: check.id
          }
        });
      }

      const updatedTarget = await tx.uptimeTarget.update({
        where: { id: target.id },
        data: {
          lastState: result.state,
          lastReason: result.reason,
          lastLatencyMs: result.latencyMs,
          lastCheckedAt: result.checkedAt,
          lastTlsExpiry: result.tlsExpiresAt,
          currentSnapshotId: snapshotId
        },
        include: TARGET_WITH_CONTEXT_INCLUDE
      });

      const snapshot = await tx.uptimeStatusSnapshot.findUniqueOrThrow({
        where: { id: snapshotId! }
      });

      return { check, snapshot, updatedTarget };
    });
  }

  private async maybeSendDigests(): Promise<void> {
    const organizations = await this.prisma.organization.findMany({
      where: {
        uptimeWebhookUrl: { not: null },
        uptimeTargets: { some: {} }
      },
      select: { id: true, name: true, uptimeWebhookUrl: true }
    });

    const now = Date.now();

    for (const org of organizations) {
      const lastSent = this.digestTracker.get(org.id) ?? 0;

      if (now - lastSent < DEFAULT_DIGEST_INTERVAL_MS) {
        continue;
      }

      const targets = await this.prisma.uptimeTarget.findMany({
        where: { organizationId: org.id },
        include: {
          currentSnapshot: true
        }
      });

      const summaryTargets = targets
        .filter((target) => target.currentSnapshot)
        .map((target) => ({
          label: target.label,
          url: target.url,
          state: target.currentSnapshot?.state ?? UptimeState.UNKNOWN,
          reason: target.currentSnapshot?.reason ?? UptimeReason.UNKNOWN,
          since: target.currentSnapshot?.since ?? new Date()
        }));

      if (org.uptimeWebhookUrl) {
        await this.notifier.sendDigest(org.uptimeWebhookUrl, org.name, summaryTargets);
        this.digestTracker.set(org.id, now);
      }
    }
  }

  private async resolveAddress(url: string): Promise<string | null> {
    try {
      const hostname = new URL(url).hostname;
      const lookup = await dns.lookup(hostname);
      return lookup.address;
    } catch {
      return null;
    }
  }

  private async resolveTlsExpiry(url: string): Promise<Date | null> {
    try {
      const parsed = new URL(url);

      if (parsed.protocol !== 'https:') {
        return null;
      }

      return await new Promise<Date | null>((resolve) => {
        const socket = tls.connect(
          {
            port: parsed.port ? Number.parseInt(parsed.port, 10) : 443,
            host: parsed.hostname,
            servername: parsed.hostname,
            timeout: 4000
          },
          () => {
            const cert = socket.getPeerCertificate();
            socket.end();

            if (cert && cert.valid_to) {
              resolve(new Date(cert.valid_to));
            } else {
              resolve(null);
            }
          }
        );

        socket.on('error', () => resolve(null));
        socket.on('timeout', () => {
          socket.destroy();
          resolve(null);
        });
      });
    } catch {
      return null;
    }
  }

  private normalizeTargetUrl(
    rawUrl: string,
    protocol?: UptimeProtocol
  ): { url: string; protocol: UptimeProtocol } {
    let parsed: URL;

    try {
      parsed = new URL(rawUrl);
    } catch {
      throw new BadRequestException('A valid URL is required for uptime monitoring.');
    }

    const scheme = parsed.protocol.replace(':', '').toUpperCase() as UptimeProtocol;

    if (scheme !== UptimeProtocol.HTTP && scheme !== UptimeProtocol.HTTPS) {
      throw new BadRequestException('Only HTTP and HTTPS protocols are supported.');
    }

    if (protocol && protocol !== scheme) {
      throw new BadRequestException('Protocol does not match the provided URL.');
    }

    return { url: parsed.toString(), protocol: scheme };
  }

  private daysUntil(date: Date): number {
    const diffMs = date.getTime() - Date.now();
    return Math.max(0, Math.ceil(diffMs / (1000 * 60 * 60 * 24)));
  }

  private toNotificationTarget(target: TargetWithContext): TargetNotificationContext {
    return {
      id: target.id,
      label: target.label,
      url: target.url,
      region: target.region,
      sensitivity: target.sensitivity,
      alertWebhookUrl: target.alertWebhookUrl,
      organization: target.organization,
      project: target.project
    };
  }

  private async ensureTargetInOrganization(
    organizationId: string,
    targetId: string
  ): Promise<{ id: string; protocol: UptimeProtocol }> {
    const target = await this.prisma.uptimeTarget.findFirst({
      where: { id: targetId, organizationId },
      select: { id: true, protocol: true }
    });

    if (!target) {
      throw new NotFoundException('Uptime target not found.');
    }

    return target;
  }

  private async ensureProjectInOrganization(projectId: string, organizationId: string) {
    const project = await this.prisma.project.findFirst({
      where: { id: projectId, organizationId },
      select: { id: true }
    });

    if (!project) {
      throw new BadRequestException('Project does not belong to this organization.');
    }
  }

  private async ensureServerInOrganization(serverId: string, organizationId: string) {
    const server = await this.prisma.server.findFirst({
      where: { id: serverId, organizationId },
      select: { id: true }
    });

    if (!server) {
      throw new BadRequestException('Server does not belong to this organization.');
    }
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

  private async ensureOrganizationOwnerAccess(
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

    if (!membership || membership.role !== Role.OWNER) {
      throw new ForbiddenException('Owner privileges are required for this action.');
    }
  }

  private scheduleNextRun(delayMs?: number) {
    if (this.scheduler) {
      clearTimeout(this.scheduler);
    }

    const wait = Math.max(MIN_SCHEDULER_INTERVAL_MS, delayMs ?? DEFAULT_SCHEDULER_INTERVAL_MS);

    this.scheduler = setTimeout(async () => {
      try {
        const nextDelay = await this.runScheduledChecks();
        this.scheduleNextRun(nextDelay);
      } catch (error) {
        this.logger.error(`Scheduled uptime run failed: ${(error as Error).message}`);
        this.scheduleNextRun();
      }
    }, wait);
  }
}
