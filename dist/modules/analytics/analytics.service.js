"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var AnalyticsService_1;
Object.defineProperty(exports, "__esModule", { value: true });
exports.AnalyticsService = void 0;
const common_1 = require("@nestjs/common");
const client_1 = require("@prisma/client");
const prisma_service_1 = require("../../prisma/prisma.service");
let AnalyticsService = AnalyticsService_1 = class AnalyticsService {
    constructor(prisma) {
        this.prisma = prisma;
    }
    async findLatencyAnomalies(user) {
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
            .filter((sample) => Boolean(sample));
        if (samples.length < AnalyticsService_1.MIN_SAMPLE_SIZE) {
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
            if (Math.abs(zScore) < AnalyticsService_1.Z_THRESHOLD) {
                return null;
            }
            return {
                reportId: sample.reportId,
                taskId: sample.taskId,
                taskLabel: sample.taskLabel,
                projectName: sample.projectName,
                organizationName: sample.organizationName,
                startedAt: sample.startedAt.toISOString(),
                metric: 'p95Ms',
                value: Number(sample.latencyMs.toFixed(2)),
                baselineMean: Number(baselineMean.toFixed(2)),
                baselineStdDev: Number(baselineStdDev.toFixed(2)),
                zScore: Number(zScore.toFixed(2)),
                successRate: sample.successRate !== null ? Number(sample.successRate.toFixed(2)) : null
            };
        })
            .filter((entry) => Boolean(entry))
            .sort((a, b) => (a.startedAt > b.startedAt ? -1 : 1));
        return anomalies;
    }
    buildScope(user) {
        if (user.role === client_1.Role.ADMINISTRATOR) {
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
    toLatencySample(report) {
        var _a;
        if (!report.summaryJson || typeof report.summaryJson !== 'object' || Array.isArray(report.summaryJson)) {
            return null;
        }
        const summary = report.summaryJson;
        const metrics = this.extractMetrics(summary.metrics);
        if (!(metrics === null || metrics === void 0 ? void 0 : metrics.p95Ms) && !(metrics === null || metrics === void 0 ? void 0 : metrics.averageMs)) {
            return null;
        }
        const latencyMs = (_a = metrics.p95Ms) !== null && _a !== void 0 ? _a : metrics.averageMs;
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
    extractMetrics(maybeMetrics) {
        var _a;
        if (!maybeMetrics ||
            typeof maybeMetrics !== 'object' ||
            Array.isArray(maybeMetrics)) {
            return null;
        }
        const metrics = maybeMetrics;
        const averageMs = this.toNumber(metrics.averageMs);
        const p95Ms = this.toNumber((_a = metrics.p95Ms) !== null && _a !== void 0 ? _a : metrics['p(95)']);
        const successRate = this.toNumber(metrics.successRate);
        return {
            averageMs,
            p95Ms,
            successRate
        };
    }
    toNumber(value) {
        if (typeof value === 'number' && Number.isFinite(value)) {
            return value;
        }
        return null;
    }
    mean(values) {
        const total = values.reduce((acc, value) => acc + value, 0);
        return total / values.length;
    }
    stdDev(values, mean) {
        const variance = values.reduce((acc, value) => acc + (value - mean) ** 2, 0) / values.length;
        return Math.sqrt(variance);
    }
};
exports.AnalyticsService = AnalyticsService;
AnalyticsService.MIN_SAMPLE_SIZE = 8;
AnalyticsService.Z_THRESHOLD = 2.25;
exports.AnalyticsService = AnalyticsService = AnalyticsService_1 = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [prisma_service_1.PrismaService])
], AnalyticsService);
//# sourceMappingURL=analytics.service.js.map