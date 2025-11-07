import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  InternalServerErrorException,
  Logger,
  NotFoundException
} from '@nestjs/common';
import type { Task, TaskReport } from '@prisma/client';
import { Prisma, Role } from '@prisma/client';
import type { Response } from 'express';
import PDFDocument = require('pdfkit');

import { PrismaService } from '../../prisma/prisma.service';
import type { AuthenticatedUser } from '../../common/types/auth-user';
import {
  CREDIT_COST_CREATE_TASK,
  CREDIT_COST_RUN_TASK
} from '../../common/constants/credit-costs';
import { TaskRunnerService } from './task-runner.service';
import { CreateTaskDto } from './dto/create-task.dto';
import { UpdateTaskDto } from './dto/update-task.dto';
import {
  InsufficientCreditsException,
  OrganizationCreditService
} from '../organization/organization-credit.service';

const SCENARIO_GUIDELINES: Record<string, {
  label: string;
  vus: string;
  duration: string;
  purpose: string;
  trigger: string;
  exit: string;
}> = {
  SMOKE: {
    label: 'SMOKE',
    vus: '2 VUs',
    duration: '30s',
    purpose: 'Confirm endpoint responds cleanly under minimal traffic.',
    trigger: 'CI/CD smoke stage or post-release validation.',
    exit: '≥99% success rate, p95 < 800 ms.'
  },
  STRESS: {
    label: 'STRESS',
    vus: '5 VUs',
    duration: '1m',
    purpose: 'Increase sustained pressure to uncover bottlenecks/ceilings.',
    trigger: 'Pre-scale testing before a high-traffic campaign.',
    exit: 'Perf degradation <10% once steady state is reached.'
  },
  SOAK: {
    label: 'SOAK',
    vus: '3 VUs',
    duration: '2m',
    purpose: 'Expose memory leaks, queue build-up, long-run throttling.',
    trigger: 'Overnight reliability checks or before long-lived events.',
    exit: 'Trend charts stay flat; resource usage returns to baseline.'
  },
  SPIKE: {
    label: 'SPIKE',
    vus: '10 VUs',
    duration: '20s',
    purpose: 'Inject bursts to check recovery from sharp demand changes.',
    trigger: 'Black-Friday-style launches, marketing spikes.',
    exit: 'Response times recover within 60s; success rate >97%.'
  },
  CUSTOM: {
    label: 'CUSTOM',
    vus: 'custom-defined',
    duration: '1m',
    purpose: 'User-defined scenarios for specific testing needs.',
    trigger: 'On-demand testing or specific event-driven tests.',
    exit: 'Defined by the user.'
  }
};

type ParsedSummary = {
  scenario?: {
    mode?: string;
    totalRequests?: number;
  };
  metrics?: {
    averageMs?: number;
    minMs?: number;
    maxMs?: number;
    p95Ms?: number;
    successRate?: number;
  };
  results?: {
    totalRequests?: number;
    successCount?: number;
    failureCount?: number;
  };
  request?: {
    method?: string;
    headers?: Record<string, string>;
    hasPayload?: boolean;
  };
  raw?: unknown;
};

@Injectable()
export class TaskService {
  private readonly logger = new Logger(TaskService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly taskRunner: TaskRunnerService,
    private readonly creditService: OrganizationCreditService
  ) {}

  async findAllByProject(projectId: string, user: AuthenticatedUser): Promise<Task[]> {
    await this.verifyProjectAccess(projectId, user);

    return this.prisma.task.findMany({
      where: { projectId },
      orderBy: { createdAt: 'desc' }
    });
  }

  async create(
    projectId: string,
    payload: CreateTaskDto,
    user: AuthenticatedUser
  ): Promise<Task> {
    const scheduleAt = this.normalizeDate(payload.scheduleAt);
    const organizationId = await this.verifyProjectAccess(projectId, user);

    const method = this.normalizeMethod(payload.method);
    const headers = this.normalizeHeaders(payload.headers);
    const body = this.normalizePayload(payload.payload);
    const customVus = this.normalizePositiveInteger(payload.customVus);
    const durationSeconds = this.normalizePositiveInteger(payload.durationSeconds);

    return this.prisma.$transaction(async (tx) => {
      await this.creditService.spendCredits(
        organizationId,
        CREDIT_COST_CREATE_TASK,
        tx,
        'create a task'
      );

      return tx.task.create({
        data: {
          projectId,
          label: payload.label,
          targetUrl: payload.targetUrl,
          mode: payload.mode,
          scheduleAt,
          method,
          headers: (headers ?? Prisma.JsonNull) as Prisma.NullableJsonNullValueInput,
          payload: body,
          customVus,
          durationSeconds
        }
      });
    });
  }

  async update(id: string, payload: UpdateTaskDto, user: AuthenticatedUser): Promise<Task> {
    const task = await this.prisma.task.findUnique({
      where: { id },
      select: { projectId: true }
    });

    if (!task) {
      throw new NotFoundException('Task not found.');
    }

    await this.verifyProjectAccess(task.projectId, user);

    const updateData: Prisma.TaskUpdateInput = {};

    if (payload.label !== undefined) {
      updateData.label = payload.label;
    }

    if (payload.targetUrl !== undefined) {
      updateData.targetUrl = payload.targetUrl;
    }

    if (payload.mode !== undefined) {
      updateData.mode = payload.mode;
    }

    if (payload.scheduleAt !== undefined) {
      updateData.scheduleAt = this.normalizeDate(payload.scheduleAt);
    }

    if (payload.method !== undefined) {
      updateData.method = this.normalizeMethod(payload.method);
    }

    if (payload.headers !== undefined) {
      const normalizedHeaders = this.normalizeHeaders(payload.headers);
      updateData.headers = (normalizedHeaders ?? Prisma.JsonNull) as Prisma.NullableJsonNullValueInput;
    }

    if (payload.payload !== undefined) {
      updateData.payload = this.normalizePayload(payload.payload);
    }

    if (payload.customVus !== undefined) {
      const customVus = this.normalizePositiveInteger(payload.customVus);
      updateData.customVus = customVus;
    }

    if (payload.durationSeconds !== undefined) {
      const durationSeconds = this.normalizePositiveInteger(payload.durationSeconds);
      updateData.durationSeconds = durationSeconds;
    }

    return this.prisma.task.update({
      where: { id },
      data: updateData
    });
  }

  async run(taskId: string, user: AuthenticatedUser): Promise<TaskReport> {
    const task = await this.prisma.task.findUnique({
      where: { id: taskId },
      select: {
        id: true,
        projectId: true,
        targetUrl: true,
        mode: true,
        method: true,
        headers: true,
        payload: true,
        customVus: true,
        durationSeconds: true
      }
    });

    if (!task) {
      throw new NotFoundException('Task not found.');
    }

    const organizationId = await this.verifyProjectAccess(task.projectId, user);

    try {
      await this.creditService.spendCredits(
        organizationId,
        CREDIT_COST_RUN_TASK,
        undefined,
        'run a task'
      );
    } catch (error) {
      if (error instanceof InsufficientCreditsException) {
        throw error;
      }
      throw error;
    }

    let result;

    try {
      result = await this.taskRunner.enqueue({
        taskId,
        targetUrl: task.targetUrl,
        mode: task.mode,
        method: this.normalizeMethod(task.method),
        headers: this.headersFromJson(task.headers),
        payload: typeof task.payload === 'string' ? task.payload : undefined,
        customVus: task.customVus ?? undefined,
        durationSeconds: task.durationSeconds ?? undefined
      });
    } catch (error) {
      await this.creditService
        .refundCredits(organizationId, CREDIT_COST_RUN_TASK)
        .catch((refundError) =>
          this.logger.error('Failed to refund credits after run failure', refundError as Error)
        );
      this.logger.error(`Failed to execute task ${taskId}`, error as Error);
      throw new InternalServerErrorException('Unable to execute load test run.');
    }

    try {
      return await this.prisma.taskReport.create({
        data: {
          taskId,
          status: result.status,
          startedAt: result.startedAt,
          completedAt: result.completedAt,
          summaryJson: result.summary ? (result.summary as Prisma.InputJsonValue) : Prisma.JsonNull
        }
      });
    } catch (error) {
      await this.creditService
        .refundCredits(organizationId, CREDIT_COST_RUN_TASK)
        .catch((refundError) =>
          this.logger.error('Failed to refund credits after report creation error', refundError as Error)
        );
      throw error;
    }
  }

  private normalizeMethod(method?: string): string {
    return (method ?? 'GET').toUpperCase();
  }

  private normalizeHeaders(
    headers?: Array<{ key?: string; value?: string }>
  ): Prisma.InputJsonValue | null {
    if (!headers || headers.length === 0) {
      return null;
    }

    const result: Record<string, string> = {};
    headers.forEach((entry) => {
      const key = entry.key?.trim().toLowerCase();
      const value = (entry.value ?? '').replace(/[\r\n]/g, '');
      if (key) {
        result[key] = value;
      }
    });

    return Object.keys(result).length > 0 ? result : null;
  }

  private headersFromJson(value: Prisma.JsonValue | null | undefined): Record<string, string> | undefined {
    if (value === null || value === undefined || typeof value !== 'object' || Array.isArray(value)) {
      return undefined;
    }

    const entries = Object.entries(value as Record<string, unknown>);
    const normalized: Record<string, string> = {};
    entries.forEach(([key, raw]) => {
      normalized[key] = typeof raw === 'string' ? raw : JSON.stringify(raw);
    });
    return normalized;
  }

  private normalizePayload(payload?: string): string | null {
    if (payload === undefined) {
      return null;
    }

    const trimmed = payload.trim();
    return trimmed.length > 0 ? trimmed : null;
  }

  private normalizePositiveInteger(value?: number | null): number | null {
    if (typeof value !== 'number' || !Number.isFinite(value)) {
      return null;
    }
    const normalized = Math.round(value);
    return normalized > 0 ? normalized : null;
  }

  async findReports(taskId: string, user: AuthenticatedUser): Promise<TaskReport[]> {
    const task = await this.prisma.task.findUnique({
      where: { id: taskId },
      select: { projectId: true }
    });

    if (!task) {
      throw new NotFoundException('Task not found.');
    }

    await this.verifyProjectAccess(task.projectId, user);

    return this.prisma.taskReport.findMany({
      where: { taskId },
      orderBy: { startedAt: 'desc' },
      take: 10
    });
  }

  async findRecentReports(user: AuthenticatedUser): Promise<
    Array<
      TaskReport & {
        task: {
          id: string;
          label: string;
          method?: string;
          targetUrl?: string | null;
          headers?: Prisma.JsonValue | null;
          payload?: string | null;
          project: {
            id: string;
            name: string;
            organization: {
              id: string;
              name: string;
              slug: string;
            };
          };
        };
      }
    >
  > {
    const where =
      user.role === Role.ADMINISTRATOR
        ? {}
        : {
            task: {
              project: {
                organization: {
                  members: {
                    some: {
                      userId: user.userId
                    }
                  }
                }
              }
            }
          };

    return this.prisma.taskReport.findMany({
      where,
      include: {
        task: {
          select: {
            id: true,
            label: true,
            method: true,
            headers: true,
            targetUrl: true,
            payload: true,
            project: {
              select: {
                id: true,
                name: true,
                organization: {
                  select: {
                    id: true,
                    name: true,
                    slug: true
                  }
                }
              }
            }
          }
        }
      },
      orderBy: { startedAt: 'desc' },
      take: 25
    });
  }

  async exportRecentReportsPdf(user: AuthenticatedUser, res: Response): Promise<void> {
    const reports = await this.findRecentReports(user);

    const doc = new PDFDocument({ margin: 50 });
    doc.pipe(res);

    doc.fontSize(20).text('Load Test Execution Summary', { align: 'center' });
    doc.moveDown();

    if (reports.length === 0) {
      doc.fontSize(12).text('No task runs available for the current scope.');
      doc.end();
      return;
    }

    const aggregate = this.buildAggregateSummary(reports);

    const now = new Date();
    const formattedDate = `${String(now.getDate()).padStart(2, '0')}/${String(
      now.getMonth() + 1
    ).padStart(2, '0')}/${now.getFullYear()}`;  
    doc.fontSize(12).text(`Generated: ${formattedDate}`);
    doc.moveDown();

    doc.fontSize(14).text('Overview', { underline: true });
    doc.moveDown(0.5);
    doc.fontSize(12)
      .text(`Runs analysed: ${aggregate.overallCount}`)
      .text(`Success rate: ${aggregate.successRate.toFixed(2)}%`)
      .text(`Dominant mode: ${aggregate.topMode}`)
      .text(
        `Average latency: ${aggregate.averageLatency !== null ? `${aggregate.averageLatency.toFixed(2)} ms` : '—'}`
      )
      .text(
        `Average P95 latency: ${aggregate.averageP95 !== null ? `${aggregate.averageP95.toFixed(2)} ms` : '—'}`
      )
      .moveDown()
      .text(`Prediction & insight: ${aggregate.recommendation}`);

    reports.forEach((report, index) => {
      const summary = this.parseSummary(report.summaryJson);
      const scenario = summary?.scenario;
      const metrics = summary?.metrics;
      const results = summary?.results;
      const request = summary?.request;
      const fallbackHeaders = this.headersFromJson(report.task.headers ?? null);
      const requestHeaderCount = request?.headers
        ? Object.keys(request.headers).length
        : fallbackHeaders
          ? Object.keys(fallbackHeaders).length
          : 0;

      doc.addPage();
      doc.fontSize(14).text(`Run ${index + 1}: ${report.task.label}`, { underline: true });
      doc.moveDown(0.5);

      const formatDMY = (d?: Date | null) => {
        if (!d) return '—';
        const day = String(d.getDate()).padStart(2, '0');
        const month = String(d.getMonth() + 1).padStart(2, '0');
        const year = d.getFullYear();
        return `${day}/${month}/${year}`;
      };

      const started = report.startedAt ? new Date(report.startedAt) : null;
      const completed = report.completedAt ? new Date(report.completedAt) : null;

      doc.fontSize(12)
        .text(`Project: ${report.task.project.name}`)
        .text(`Organization: ${report.task.project.organization.name}`)
        //add target URL
        .text(`Target URL: ${report.task.targetUrl ? report.task.targetUrl : 'N/A'}`)
        .text(`Status: ${report.status.toUpperCase()}`)
        .text(`Started: ${formatDMY(started)}`)
        .text(`Completed: ${formatDMY(completed)}`)
        .moveDown(0.5);
      if (scenario) {
        doc.text(`Scenario mode: ${scenario.mode ?? '—'}`);
        doc.text(`Guidelines:`);
        const guidelines = SCENARIO_GUIDELINES[scenario.mode ?? 'SMOKE'] || SCENARIO_GUIDELINES.SMOKE;
        doc.text(`  - VUs: ${guidelines.vus}`);
        doc.text(`  - Duration: ${guidelines.duration}`);
        doc.text(`  - Purpose: ${guidelines.purpose}`);
        doc.text(`  - Trigger: ${guidelines.trigger}`);
        doc.text(`  - Exit Criteria: ${guidelines.exit}`);
        doc.text(`Total requests: ${scenario.totalRequests ?? '—'}`);
      }
      //add duration on seconds from report.startedAt and report.completedAt
        if (report.completedAt) {
          const durationMs = report.completedAt.getTime() - report.startedAt.getTime();
          const durationSec = (durationMs / 1000).toFixed(2);
          doc.text(`Test Duration: ${durationSec} seconds`);
        } else {
          doc.text(`Test Duration: —`);
        }
      if (metrics) {
        doc.text(
          `Avg latency: ${typeof metrics.averageMs === 'number' ? `${metrics.averageMs.toFixed(2)} ms` : '—'}`
        );
        doc.text(
          `P95 latency: ${typeof metrics.p95Ms === 'number' ? `${metrics.p95Ms.toFixed(2)} ms` : '—'}`
        );
        doc.text(
          `Success rate: ${typeof metrics.successRate === 'number' ? `${metrics.successRate.toFixed(2)}%` : '—'}`
        );
      }
      if (results) {
        doc.text(`Success responses: ${results.successCount ?? '—'}`);
        doc.text(`Failed responses: ${results.failureCount ?? '—'}`);
      }
      if (request) {
        doc.text(`HTTP method: ${request.method ?? report.task.method ?? 'GET'}`);
        doc.text(`Headers: ${requestHeaderCount}`);
        doc.text(`Payload included: ${request.hasPayload ? 'Yes' : 'No'}`);
      } else {
        doc.text(`HTTP method: ${report.task.method ?? 'GET'}`);
        doc.text(`Headers: ${requestHeaderCount}`);
        doc.text(`Payload included: ${fallbackHeaders ? 'Yes' : 'No'}`);
      }

      const requestHeaders = (() => {
        const source = request?.headers ?? fallbackHeaders;
        if (!source || typeof source !== 'object') {
          return undefined;
        }
        const entries = Object.entries(source as Record<string, unknown>);
        return entries.reduce<Record<string, string>>((acc, [key, value]) => {
          acc[key] = typeof value === 'string' ? value : JSON.stringify(value);
          return acc;
        }, {});
      })();
      const payload = report.task.payload;

      if (requestHeaders && Object.keys(requestHeaders).length > 0) {
        doc.moveDown();
        doc.text('Request Headers:', { underline: true });
        doc.moveDown(0.5);
        Object.entries(requestHeaders).forEach(([headerKey, headerValue]) => {
          doc.text(`${headerKey}: ${headerValue}`);
        });
      }

      if (typeof payload === 'string' && payload.trim().length > 0) {
        doc.moveDown();
        doc.text('Request Payload:', { underline: true });
        doc.moveDown(0.5);
        doc.font('Courier');
        doc.text(payload, { width: 500 });
        doc.font('Helvetica');
      }
    });

    doc.end();
  }

  private buildAggregateSummary(
    reports: Array<
      TaskReport & {
        task: {
          id: string;
          label: string;
          method?: string;
          headers?: Prisma.JsonValue | null;
          project: {
            id: string;
            name: string;
            organization: {
              id: string;
              name: string;
              slug: string;
            };
          };
        };
      }
    >
  ) {
    let successCount = 0;
    const modeCounts: Record<string, number> = {};
    let totalAvg = 0;
    let totalP95 = 0;
    let latencySamples = 0;

    reports.forEach((report) => {
      if (report.status.toLowerCase() === 'completed') {
        successCount += 1;
      }

      const summary = this.parseSummary(report.summaryJson);
      const mode = summary?.scenario?.mode ?? report.task.label;
      if (mode) {
        modeCounts[mode] = (modeCounts[mode] ?? 0) + 1;
      }

      if (typeof summary?.metrics?.averageMs === 'number') {
        totalAvg += summary.metrics.averageMs;
        latencySamples += 1;
      }

      if (typeof summary?.metrics?.p95Ms === 'number') {
        totalP95 += summary.metrics.p95Ms;
      }
    });

    const overallCount = reports.length;
    const successRate = (successCount / overallCount) * 100;
    const topMode = Object.entries(modeCounts).sort((a, b) => b[1] - a[1])[0]?.[0] ?? '—';
    const averageLatency = latencySamples ? totalAvg / latencySamples : null;
    const averageP95 = latencySamples ? totalP95 / latencySamples : null;

    let recommendation = 'Healthy baseline; continue to monitor trending latency.';
    if (successRate < 95) {
      recommendation = 'Elevated failure rate detected; prioritize investigating degraded tasks.';
    } else if (averageP95 && averageP95 > 1200) {
      recommendation = 'High P95 latency suggests capacity issues; consider scaling or tuning scenarios.';
    }

    return {
      overallCount,
      successRate,
      topMode,
      averageLatency,
      averageP95,
      recommendation
    };
  }

  private parseSummary(input: Prisma.JsonValue | null | undefined): ParsedSummary | null {
    if (!input || typeof input !== 'object' || Array.isArray(input)) {
      return null;
    }

    const record = input as Record<string, unknown>;
    const summary: ParsedSummary = {};

    if (record.scenario && typeof record.scenario === 'object' && record.scenario !== null && !Array.isArray(record.scenario)) {
      const scenarioRecord = record.scenario as Record<string, unknown>;
      summary.scenario = {
        mode: typeof scenarioRecord.mode === 'string' ? scenarioRecord.mode : undefined,
        totalRequests:
          typeof scenarioRecord.totalRequests === 'number' ? scenarioRecord.totalRequests : undefined
      };
    }

    if (record.metrics && typeof record.metrics === 'object' && record.metrics !== null && !Array.isArray(record.metrics)) {
      const metricRecord = record.metrics as Record<string, unknown>;
      summary.metrics = {
        averageMs: typeof metricRecord.averageMs === 'number' ? metricRecord.averageMs : undefined,
        minMs: typeof metricRecord.minMs === 'number' ? metricRecord.minMs : undefined,
        maxMs: typeof metricRecord.maxMs === 'number' ? metricRecord.maxMs : undefined,
        p95Ms: typeof metricRecord.p95Ms === 'number' ? metricRecord.p95Ms : undefined,
        successRate:
          typeof metricRecord.successRate === 'number' ? metricRecord.successRate : undefined
      };
    }

    if (record.results && typeof record.results === 'object' && record.results !== null && !Array.isArray(record.results)) {
      const resultsRecord = record.results as Record<string, unknown>;
      summary.results = {
        totalRequests:
          typeof resultsRecord.totalRequests === 'number' ? resultsRecord.totalRequests : undefined,
        successCount:
          typeof resultsRecord.successCount === 'number' ? resultsRecord.successCount : undefined,
        failureCount:
          typeof resultsRecord.failureCount === 'number' ? resultsRecord.failureCount : undefined
      };
    }

    if (record.request && typeof record.request === 'object' && record.request !== null && !Array.isArray(record.request)) {
      const requestRecord = record.request as Record<string, unknown>;
      summary.request = {
        method: typeof requestRecord.method === 'string' ? requestRecord.method : undefined,
        headers:
          requestRecord.headers && typeof requestRecord.headers === 'object' && !Array.isArray(requestRecord.headers)
            ? Object.entries(requestRecord.headers as Record<string, unknown>).reduce<Record<string, string>>(
                (acc, [key, value]) => {
                  acc[key] = typeof value === 'string' ? value : JSON.stringify(value);
                  return acc;
                },
                {}
              )
            : undefined,
        hasPayload: typeof requestRecord.hasPayload === 'boolean' ? requestRecord.hasPayload : undefined
      };
    }

    if (record.raw !== undefined) {
      summary.raw = record.raw;
    }

    return summary;
  }

  private normalizeDate(value?: string): Date | null {
    if (!value) {
      return null;
    }

    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) {
      throw new BadRequestException('scheduleAt must be a valid ISO 8601 date string');
    }

    return parsed;
  }

  private async verifyProjectAccess(
    projectId: string,
    user: AuthenticatedUser
  ): Promise<string> {
    const project = await this.prisma.project.findUnique({
      where: { id: projectId },
      select: { organizationId: true }
    });

    if (!project) {
      throw new NotFoundException('Project not found.');
    }

    if (user.role === Role.ADMINISTRATOR) {
      return project.organizationId;
    }

    const membership = await this.prisma.organizationMember.findFirst({
      where: {
        organizationId: project.organizationId,
        userId: user.userId
      },
      select: { id: true }
    });

    if (!membership) {
      throw new ForbiddenException('You do not have access to this project.');
    }

    return project.organizationId;
  }
}
