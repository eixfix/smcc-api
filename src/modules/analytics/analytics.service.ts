import { Injectable } from '@nestjs/common';
import { Prisma, Role } from '@prisma/client';

import type { AuthenticatedUser } from '../../common/types/auth-user';
import { PrismaService } from '../../prisma/prisma.service';

type LatencySample = {
  reportId: string;
  taskId: string;
  taskLabel: string;
  projectName: string;
  organizationName: string;
  startedAt: Date;
  latencyMs: number;
  successRate: number | null;
};

export type LatencyAnomaly = {
  reportId: string;
  taskId: string;
  taskLabel: string;
  projectName: string;
  organizationName: string;
  startedAt: string;
  metric: 'p95Ms';
  value: number;
  baselineMean: number;
  baselineStdDev: number;
  zScore: number;
  successRate: number | null;
};

@Injectable()
export class AnalyticsService {
  private static readonly MIN_SAMPLE_SIZE = 8;
  private static readonly Z_THRESHOLD = 2.25;

  constructor(private readonly prisma: PrismaService) {}

  async findLatencyAnomalies(user: AuthenticatedUser): Promise<LatencyAnomaly[]> {
    const reports = await this.prisma.taskReport.findMany({
      where: this.buildScope(user),
      include: {
        task: {
          select: {
            id: true,
            label: true,
            project: {
              select: {
                name: true,
                organization: {
                  select: {
                    name: true
                  }
                }
              }
            }
          }
        }
      },
      orderBy: { startedAt: 'desc' },
      take: 100
    });

    const samples = reports
      .map((report) => this.toLatencySample(report))
      .filter((sample): sample is LatencySample => Boolean(sample));

    if (samples.length < AnalyticsService.MIN_SAMPLE_SIZE) {
      return [];
    }

    const baselineMean = this.mean(samples.map((sample) => sample.latencyMs));
    const baselineStdDev = this.stdDev(samples.map((sample) => sample.latencyMs), baselineMean);

    if (!baselineStdDev || Number.isNaN(baselineStdDev)) {
      return [];
    }

    const anomalies = samples
      .map((sample) => {
        const zScore = (sample.latencyMs - baselineMean) / baselineStdDev;
        if (Math.abs(zScore) < AnalyticsService.Z_THRESHOLD) {
          return null;
        }

        return {
          reportId: sample.reportId,
          taskId: sample.taskId,
          taskLabel: sample.taskLabel,
          projectName: sample.projectName,
          organizationName: sample.organizationName,
          startedAt: sample.startedAt.toISOString(),
          metric: 'p95Ms' as const,
          value: Number(sample.latencyMs.toFixed(2)),
          baselineMean: Number(baselineMean.toFixed(2)),
          baselineStdDev: Number(baselineStdDev.toFixed(2)),
          zScore: Number(zScore.toFixed(2)),
          successRate:
            sample.successRate !== null ? Number(sample.successRate.toFixed(2)) : null
        };
      })
      .filter((entry): entry is LatencyAnomaly => Boolean(entry))
      .sort((a, b) => (a.startedAt > b.startedAt ? -1 : 1));

    return anomalies;
  }

  private buildScope(user: AuthenticatedUser): Prisma.TaskReportWhereInput {
    if (user.role === Role.ADMINISTRATOR) {
      return {};
    }

    return {
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
  }

  private toLatencySample(report: {
    id: string;
    startedAt: Date;
    summaryJson: Prisma.JsonValue | null;
    task: {
      id: string;
      label: string;
      project: {
        name: string;
        organization: {
          name: string;
        };
      };
    };
  }): LatencySample | null {
    if (!report.summaryJson || typeof report.summaryJson !== 'object' || Array.isArray(report.summaryJson)) {
      return null;
    }

    const summary = report.summaryJson as Record<string, unknown>;
    const metrics = this.extractMetrics(summary.metrics);

    if (!metrics?.p95Ms && !metrics?.averageMs) {
      return null;
    }

    const latencyMs = metrics.p95Ms ?? metrics.averageMs;

    if (latencyMs === null) {
      return null;
    }

    return {
      reportId: report.id,
      taskId: report.task.id,
      taskLabel: report.task.label,
      projectName: report.task.project.name,
      organizationName: report.task.project.organization.name,
      startedAt: report.startedAt,
      latencyMs,
      successRate: metrics.successRate
    };
  }

  private extractMetrics(
    maybeMetrics: unknown
  ): { averageMs: number | null; p95Ms: number | null; successRate: number | null } | null {
    if (
      !maybeMetrics ||
      typeof maybeMetrics !== 'object' ||
      Array.isArray(maybeMetrics)
    ) {
      return null;
    }

    const metrics = maybeMetrics as Record<string, unknown>;
    const averageMs = this.toNumber(metrics.averageMs);
    const p95Ms = this.toNumber(metrics.p95Ms ?? metrics['p(95)']);
    const successRate = this.toNumber(metrics.successRate);

    return {
      averageMs,
      p95Ms,
      successRate
    };
  }

  private toNumber(value: unknown): number | null {
    if (typeof value === 'number' && Number.isFinite(value)) {
      return value;
    }

    return null;
  }

  private mean(values: number[]): number {
    const total = values.reduce((acc, value) => acc + value, 0);
    return total / values.length;
  }

  private stdDev(values: number[], mean: number): number {
    const variance =
      values.reduce((acc, value) => acc + (value - mean) ** 2, 0) / values.length;
    return Math.sqrt(variance);
  }
}
