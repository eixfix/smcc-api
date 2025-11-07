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
var TaskService_1;
Object.defineProperty(exports, "__esModule", { value: true });
exports.TaskService = void 0;
const common_1 = require("@nestjs/common");
const client_1 = require("@prisma/client");
const PDFDocument = require("pdfkit");
const prisma_service_1 = require("../../prisma/prisma.service");
const credit_costs_1 = require("../../common/constants/credit-costs");
const task_runner_service_1 = require("./task-runner.service");
const organization_credit_service_1 = require("../organization/organization-credit.service");
const SCENARIO_GUIDELINES = {
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
let TaskService = TaskService_1 = class TaskService {
    constructor(prisma, taskRunner, creditService) {
        this.prisma = prisma;
        this.taskRunner = taskRunner;
        this.creditService = creditService;
        this.logger = new common_1.Logger(TaskService_1.name);
    }
    async findAllByProject(projectId, user) {
        await this.verifyProjectAccess(projectId, user);
        return this.prisma.task.findMany({
            where: { projectId },
            orderBy: { createdAt: 'desc' }
        });
    }
    async create(projectId, payload, user) {
        const scheduleAt = this.normalizeDate(payload.scheduleAt);
        const organizationId = await this.verifyProjectAccess(projectId, user);
        const method = this.normalizeMethod(payload.method);
        const headers = this.normalizeHeaders(payload.headers);
        const body = this.normalizePayload(payload.payload);
        const customVus = this.normalizePositiveInteger(payload.customVus);
        const durationSeconds = this.normalizePositiveInteger(payload.durationSeconds);
        return this.prisma.$transaction(async (tx) => {
            await this.creditService.spendCredits(organizationId, credit_costs_1.CREDIT_COST_CREATE_TASK, tx, 'create a task');
            return tx.task.create({
                data: {
                    projectId,
                    label: payload.label,
                    targetUrl: payload.targetUrl,
                    mode: payload.mode,
                    scheduleAt,
                    method,
                    headers: (headers !== null && headers !== void 0 ? headers : client_1.Prisma.JsonNull),
                    payload: body,
                    customVus,
                    durationSeconds
                }
            });
        });
    }
    async update(id, payload, user) {
        const task = await this.prisma.task.findUnique({
            where: { id },
            select: { projectId: true }
        });
        if (!task) {
            throw new common_1.NotFoundException('Task not found.');
        }
        await this.verifyProjectAccess(task.projectId, user);
        const updateData = {};
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
            updateData.headers = (normalizedHeaders !== null && normalizedHeaders !== void 0 ? normalizedHeaders : client_1.Prisma.JsonNull);
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
    async run(taskId, user) {
        var _a, _b;
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
            throw new common_1.NotFoundException('Task not found.');
        }
        const organizationId = await this.verifyProjectAccess(task.projectId, user);
        try {
            await this.creditService.spendCredits(organizationId, credit_costs_1.CREDIT_COST_RUN_TASK, undefined, 'run a task');
        }
        catch (error) {
            if (error instanceof organization_credit_service_1.InsufficientCreditsException) {
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
                customVus: (_a = task.customVus) !== null && _a !== void 0 ? _a : undefined,
                durationSeconds: (_b = task.durationSeconds) !== null && _b !== void 0 ? _b : undefined
            });
        }
        catch (error) {
            await this.creditService
                .refundCredits(organizationId, credit_costs_1.CREDIT_COST_RUN_TASK)
                .catch((refundError) => this.logger.error('Failed to refund credits after run failure', refundError));
            this.logger.error(`Failed to execute task ${taskId}`, error);
            throw new common_1.InternalServerErrorException('Unable to execute load test run.');
        }
        try {
            return await this.prisma.taskReport.create({
                data: {
                    taskId,
                    status: result.status,
                    startedAt: result.startedAt,
                    completedAt: result.completedAt,
                    summaryJson: result.summary ? result.summary : client_1.Prisma.JsonNull
                }
            });
        }
        catch (error) {
            await this.creditService
                .refundCredits(organizationId, credit_costs_1.CREDIT_COST_RUN_TASK)
                .catch((refundError) => this.logger.error('Failed to refund credits after report creation error', refundError));
            throw error;
        }
    }
    normalizeMethod(method) {
        return (method !== null && method !== void 0 ? method : 'GET').toUpperCase();
    }
    normalizeHeaders(headers) {
        if (!headers || headers.length === 0) {
            return null;
        }
        const result = {};
        headers.forEach((entry) => {
            var _a, _b;
            const key = (_a = entry.key) === null || _a === void 0 ? void 0 : _a.trim().toLowerCase();
            const value = ((_b = entry.value) !== null && _b !== void 0 ? _b : '').replace(/[\r\n]/g, '');
            if (key) {
                result[key] = value;
            }
        });
        return Object.keys(result).length > 0 ? result : null;
    }
    headersFromJson(value) {
        if (value === null || value === undefined || typeof value !== 'object' || Array.isArray(value)) {
            return undefined;
        }
        const entries = Object.entries(value);
        const normalized = {};
        entries.forEach(([key, raw]) => {
            normalized[key] = typeof raw === 'string' ? raw : JSON.stringify(raw);
        });
        return normalized;
    }
    normalizePayload(payload) {
        if (payload === undefined) {
            return null;
        }
        const trimmed = payload.trim();
        return trimmed.length > 0 ? trimmed : null;
    }
    normalizePositiveInteger(value) {
        if (typeof value !== 'number' || !Number.isFinite(value)) {
            return null;
        }
        const normalized = Math.round(value);
        return normalized > 0 ? normalized : null;
    }
    async findReports(taskId, user) {
        const task = await this.prisma.task.findUnique({
            where: { id: taskId },
            select: { projectId: true }
        });
        if (!task) {
            throw new common_1.NotFoundException('Task not found.');
        }
        await this.verifyProjectAccess(task.projectId, user);
        return this.prisma.taskReport.findMany({
            where: { taskId },
            orderBy: { startedAt: 'desc' },
            take: 10
        });
    }
    async findRecentReports(user) {
        const where = user.role === client_1.Role.ADMINISTRATOR
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
    async exportRecentReportsPdf(user, res) {
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
        const formattedDate = `${String(now.getDate()).padStart(2, '0')}/${String(now.getMonth() + 1).padStart(2, '0')}/${now.getFullYear()}`;
        doc.fontSize(12).text(`Generated: ${formattedDate}`);
        doc.moveDown();
        doc.fontSize(14).text('Overview', { underline: true });
        doc.moveDown(0.5);
        doc.fontSize(12)
            .text(`Runs analysed: ${aggregate.overallCount}`)
            .text(`Success rate: ${aggregate.successRate.toFixed(2)}%`)
            .text(`Dominant mode: ${aggregate.topMode}`)
            .text(`Average latency: ${aggregate.averageLatency !== null ? `${aggregate.averageLatency.toFixed(2)} ms` : '—'}`)
            .text(`Average P95 latency: ${aggregate.averageP95 !== null ? `${aggregate.averageP95.toFixed(2)} ms` : '—'}`)
            .moveDown()
            .text(`Prediction & insight: ${aggregate.recommendation}`);
        reports.forEach((report, index) => {
            var _a, _b, _c, _d, _e, _f, _g, _h, _j;
            const summary = this.parseSummary(report.summaryJson);
            const scenario = summary === null || summary === void 0 ? void 0 : summary.scenario;
            const metrics = summary === null || summary === void 0 ? void 0 : summary.metrics;
            const results = summary === null || summary === void 0 ? void 0 : summary.results;
            const request = summary === null || summary === void 0 ? void 0 : summary.request;
            const fallbackHeaders = this.headersFromJson((_a = report.task.headers) !== null && _a !== void 0 ? _a : null);
            const requestHeaderCount = (request === null || request === void 0 ? void 0 : request.headers)
                ? Object.keys(request.headers).length
                : fallbackHeaders
                    ? Object.keys(fallbackHeaders).length
                    : 0;
            doc.addPage();
            doc.fontSize(14).text(`Run ${index + 1}: ${report.task.label}`, { underline: true });
            doc.moveDown(0.5);
            const formatDMY = (d) => {
                if (!d)
                    return '—';
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
                .text(`Target URL: ${report.task.targetUrl ? report.task.targetUrl : 'N/A'}`)
                .text(`Status: ${report.status.toUpperCase()}`)
                .text(`Started: ${formatDMY(started)}`)
                .text(`Completed: ${formatDMY(completed)}`)
                .moveDown(0.5);
            if (scenario) {
                doc.text(`Scenario mode: ${(_b = scenario.mode) !== null && _b !== void 0 ? _b : '—'}`);
                doc.text(`Guidelines:`);
                const guidelines = SCENARIO_GUIDELINES[(_c = scenario.mode) !== null && _c !== void 0 ? _c : 'SMOKE'] || SCENARIO_GUIDELINES.SMOKE;
                doc.text(`  - VUs: ${guidelines.vus}`);
                doc.text(`  - Duration: ${guidelines.duration}`);
                doc.text(`  - Purpose: ${guidelines.purpose}`);
                doc.text(`  - Trigger: ${guidelines.trigger}`);
                doc.text(`  - Exit Criteria: ${guidelines.exit}`);
                doc.text(`Total requests: ${(_d = scenario.totalRequests) !== null && _d !== void 0 ? _d : '—'}`);
            }
            if (report.completedAt) {
                const durationMs = report.completedAt.getTime() - report.startedAt.getTime();
                const durationSec = (durationMs / 1000).toFixed(2);
                doc.text(`Test Duration: ${durationSec} seconds`);
            }
            else {
                doc.text(`Test Duration: —`);
            }
            if (metrics) {
                doc.text(`Avg latency: ${typeof metrics.averageMs === 'number' ? `${metrics.averageMs.toFixed(2)} ms` : '—'}`);
                doc.text(`P95 latency: ${typeof metrics.p95Ms === 'number' ? `${metrics.p95Ms.toFixed(2)} ms` : '—'}`);
                doc.text(`Success rate: ${typeof metrics.successRate === 'number' ? `${metrics.successRate.toFixed(2)}%` : '—'}`);
            }
            if (results) {
                doc.text(`Success responses: ${(_e = results.successCount) !== null && _e !== void 0 ? _e : '—'}`);
                doc.text(`Failed responses: ${(_f = results.failureCount) !== null && _f !== void 0 ? _f : '—'}`);
            }
            if (request) {
                doc.text(`HTTP method: ${(_h = (_g = request.method) !== null && _g !== void 0 ? _g : report.task.method) !== null && _h !== void 0 ? _h : 'GET'}`);
                doc.text(`Headers: ${requestHeaderCount}`);
                doc.text(`Payload included: ${request.hasPayload ? 'Yes' : 'No'}`);
            }
            else {
                doc.text(`HTTP method: ${(_j = report.task.method) !== null && _j !== void 0 ? _j : 'GET'}`);
                doc.text(`Headers: ${requestHeaderCount}`);
                doc.text(`Payload included: ${fallbackHeaders ? 'Yes' : 'No'}`);
            }
            const requestHeaders = (() => {
                var _a;
                const source = (_a = request === null || request === void 0 ? void 0 : request.headers) !== null && _a !== void 0 ? _a : fallbackHeaders;
                if (!source || typeof source !== 'object') {
                    return undefined;
                }
                const entries = Object.entries(source);
                return entries.reduce((acc, [key, value]) => {
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
    buildAggregateSummary(reports) {
        var _a, _b;
        let successCount = 0;
        const modeCounts = {};
        let totalAvg = 0;
        let totalP95 = 0;
        let latencySamples = 0;
        reports.forEach((report) => {
            var _a, _b, _c, _d, _e;
            if (report.status.toLowerCase() === 'completed') {
                successCount += 1;
            }
            const summary = this.parseSummary(report.summaryJson);
            const mode = (_b = (_a = summary === null || summary === void 0 ? void 0 : summary.scenario) === null || _a === void 0 ? void 0 : _a.mode) !== null && _b !== void 0 ? _b : report.task.label;
            if (mode) {
                modeCounts[mode] = ((_c = modeCounts[mode]) !== null && _c !== void 0 ? _c : 0) + 1;
            }
            if (typeof ((_d = summary === null || summary === void 0 ? void 0 : summary.metrics) === null || _d === void 0 ? void 0 : _d.averageMs) === 'number') {
                totalAvg += summary.metrics.averageMs;
                latencySamples += 1;
            }
            if (typeof ((_e = summary === null || summary === void 0 ? void 0 : summary.metrics) === null || _e === void 0 ? void 0 : _e.p95Ms) === 'number') {
                totalP95 += summary.metrics.p95Ms;
            }
        });
        const overallCount = reports.length;
        const successRate = (successCount / overallCount) * 100;
        const topMode = (_b = (_a = Object.entries(modeCounts).sort((a, b) => b[1] - a[1])[0]) === null || _a === void 0 ? void 0 : _a[0]) !== null && _b !== void 0 ? _b : '—';
        const averageLatency = latencySamples ? totalAvg / latencySamples : null;
        const averageP95 = latencySamples ? totalP95 / latencySamples : null;
        let recommendation = 'Healthy baseline; continue to monitor trending latency.';
        if (successRate < 95) {
            recommendation = 'Elevated failure rate detected; prioritize investigating degraded tasks.';
        }
        else if (averageP95 && averageP95 > 1200) {
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
    parseSummary(input) {
        if (!input || typeof input !== 'object' || Array.isArray(input)) {
            return null;
        }
        const record = input;
        const summary = {};
        if (record.scenario && typeof record.scenario === 'object' && record.scenario !== null && !Array.isArray(record.scenario)) {
            const scenarioRecord = record.scenario;
            summary.scenario = {
                mode: typeof scenarioRecord.mode === 'string' ? scenarioRecord.mode : undefined,
                totalRequests: typeof scenarioRecord.totalRequests === 'number' ? scenarioRecord.totalRequests : undefined
            };
        }
        if (record.metrics && typeof record.metrics === 'object' && record.metrics !== null && !Array.isArray(record.metrics)) {
            const metricRecord = record.metrics;
            summary.metrics = {
                averageMs: typeof metricRecord.averageMs === 'number' ? metricRecord.averageMs : undefined,
                minMs: typeof metricRecord.minMs === 'number' ? metricRecord.minMs : undefined,
                maxMs: typeof metricRecord.maxMs === 'number' ? metricRecord.maxMs : undefined,
                p95Ms: typeof metricRecord.p95Ms === 'number' ? metricRecord.p95Ms : undefined,
                successRate: typeof metricRecord.successRate === 'number' ? metricRecord.successRate : undefined
            };
        }
        if (record.results && typeof record.results === 'object' && record.results !== null && !Array.isArray(record.results)) {
            const resultsRecord = record.results;
            summary.results = {
                totalRequests: typeof resultsRecord.totalRequests === 'number' ? resultsRecord.totalRequests : undefined,
                successCount: typeof resultsRecord.successCount === 'number' ? resultsRecord.successCount : undefined,
                failureCount: typeof resultsRecord.failureCount === 'number' ? resultsRecord.failureCount : undefined
            };
        }
        if (record.request && typeof record.request === 'object' && record.request !== null && !Array.isArray(record.request)) {
            const requestRecord = record.request;
            summary.request = {
                method: typeof requestRecord.method === 'string' ? requestRecord.method : undefined,
                headers: requestRecord.headers && typeof requestRecord.headers === 'object' && !Array.isArray(requestRecord.headers)
                    ? Object.entries(requestRecord.headers).reduce((acc, [key, value]) => {
                        acc[key] = typeof value === 'string' ? value : JSON.stringify(value);
                        return acc;
                    }, {})
                    : undefined,
                hasPayload: typeof requestRecord.hasPayload === 'boolean' ? requestRecord.hasPayload : undefined
            };
        }
        if (record.raw !== undefined) {
            summary.raw = record.raw;
        }
        return summary;
    }
    normalizeDate(value) {
        if (!value) {
            return null;
        }
        const parsed = new Date(value);
        if (Number.isNaN(parsed.getTime())) {
            throw new common_1.BadRequestException('scheduleAt must be a valid ISO 8601 date string');
        }
        return parsed;
    }
    async verifyProjectAccess(projectId, user) {
        const project = await this.prisma.project.findUnique({
            where: { id: projectId },
            select: { organizationId: true }
        });
        if (!project) {
            throw new common_1.NotFoundException('Project not found.');
        }
        if (user.role === client_1.Role.ADMINISTRATOR) {
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
            throw new common_1.ForbiddenException('You do not have access to this project.');
        }
        return project.organizationId;
    }
};
exports.TaskService = TaskService;
exports.TaskService = TaskService = TaskService_1 = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [prisma_service_1.PrismaService,
        task_runner_service_1.TaskRunnerService,
        organization_credit_service_1.OrganizationCreditService])
], TaskService);
//# sourceMappingURL=task.service.js.map