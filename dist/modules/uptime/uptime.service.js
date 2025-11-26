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
var _a, _b;
var UptimeService_1;
Object.defineProperty(exports, "__esModule", { value: true });
exports.UptimeService = void 0;
const common_1 = require("@nestjs/common");
const client_1 = require("@prisma/client");
const dns = require("node:dns/promises");
const tls = require("node:tls");
const prisma_service_1 = require("../../prisma/prisma.service");
const uptime_notifier_service_1 = require("./uptime-notifier.service");
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
};
const DEFAULT_SCHEDULER_INTERVAL_MS = Number((_a = process.env.UPTIME_SCHEDULER_INTERVAL_MS) !== null && _a !== void 0 ? _a : 5 * 60 * 1000);
const MIN_SCHEDULER_INTERVAL_MS = 1000;
const DEFAULT_DIGEST_INTERVAL_MS = Number((_b = process.env.UPTIME_DIGEST_INTERVAL_MS) !== null && _b !== void 0 ? _b : 4.8 * 60 * 60 * 1000);
let UptimeService = UptimeService_1 = class UptimeService {
    constructor(prisma, notifier) {
        this.prisma = prisma;
        this.notifier = notifier;
        this.logger = new common_1.Logger(UptimeService_1.name);
        this.scheduler = null;
        this.digestTracker = new Map();
    }
    async onModuleInit() {
        if (process.env.UPTIME_SCHEDULER_ENABLED === 'false') {
            this.logger.log('Uptime scheduler disabled via env flag.');
            return;
        }
        this.scheduleNextRun(0);
    }
    async onModuleDestroy() {
        if (this.scheduler) {
            clearTimeout(this.scheduler);
            this.scheduler = null;
        }
    }
    async listTargets(organizationId, user) {
        await this.ensureOrganizationReadAccess(organizationId, user);
        return this.prisma.uptimeTarget.findMany({
            where: { organizationId },
            orderBy: { createdAt: 'desc' },
            include: TARGET_WITH_CONTEXT_INCLUDE
        });
    }
    async getTarget(organizationId, targetId, user) {
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
            throw new common_1.NotFoundException('Uptime target not found.');
        }
        const { checks, ...rest } = target;
        return { ...rest, recentChecks: checks };
    }
    async listChecks(organizationId, targetId, user, limit) {
        await this.ensureOrganizationReadAccess(organizationId, user);
        await this.ensureTargetInOrganization(organizationId, targetId);
        const take = Math.min(Math.max(limit !== null && limit !== void 0 ? limit : 25, 1), 200);
        return this.prisma.uptimeCheck.findMany({
            where: { targetId },
            orderBy: { checkedAt: 'desc' },
            take
        });
    }
    async createTarget(organizationId, payload, user) {
        await this.ensureOrganizationOwnerAccess(organizationId, user);
        if (payload.projectId) {
            await this.ensureProjectInOrganization(payload.projectId, organizationId);
        }
        if (payload.serverId) {
            await this.ensureServerInOrganization(payload.serverId, organizationId);
        }
        const normalized = this.normalizeTargetUrl(payload.url, payload.protocol);
        return this.prisma.$transaction(async (tx) => {
            var _a, _b, _c, _d;
            const target = await tx.uptimeTarget.create({
                data: {
                    organizationId,
                    projectId: payload.projectId,
                    serverId: payload.serverId,
                    label: payload.label,
                    url: normalized.url,
                    protocol: normalized.protocol,
                    region: payload.region,
                    sensitivity: (_a = payload.sensitivity) !== null && _a !== void 0 ? _a : client_1.UptimeSensitivity.PRODUCTION,
                    checkIntervalSeconds: (_b = payload.checkIntervalSeconds) !== null && _b !== void 0 ? _b : 300,
                    requestTimeoutMs: (_c = payload.requestTimeoutMs) !== null && _c !== void 0 ? _c : 5000,
                    expectedStatus: payload.expectedStatus,
                    alertWebhookUrl: payload.alertWebhookUrl,
                    isPaused: (_d = payload.isPaused) !== null && _d !== void 0 ? _d : false
                }
            });
            const snapshot = await tx.uptimeStatusSnapshot.create({
                data: {
                    targetId: target.id,
                    state: client_1.UptimeState.UNKNOWN,
                    reason: client_1.UptimeReason.UNKNOWN,
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
    async updateTarget(organizationId, targetId, payload, user) {
        var _a;
        await this.ensureOrganizationOwnerAccess(organizationId, user);
        const target = await this.ensureTargetInOrganization(organizationId, targetId);
        if (payload.projectId) {
            await this.ensureProjectInOrganization(payload.projectId, organizationId);
        }
        if (payload.serverId) {
            await this.ensureServerInOrganization(payload.serverId, organizationId);
        }
        const normalized = payload.url
            ? this.normalizeTargetUrl(payload.url, (_a = payload.protocol) !== null && _a !== void 0 ? _a : target.protocol)
            : null;
        return this.prisma.uptimeTarget.update({
            where: { id: targetId },
            data: {
                projectId: payload.projectId,
                serverId: payload.serverId,
                label: payload.label,
                url: normalized === null || normalized === void 0 ? void 0 : normalized.url,
                protocol: normalized === null || normalized === void 0 ? void 0 : normalized.protocol,
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
    async runCheckNow(organizationId, targetId, user) {
        await this.ensureOrganizationReadAccess(organizationId, user);
        const target = await this.prisma.uptimeTarget.findFirst({
            where: { id: targetId, organizationId },
            include: TARGET_WITH_CONTEXT_INCLUDE
        });
        if (!target) {
            throw new common_1.NotFoundException('Uptime target not found.');
        }
        return this.runProbeForTarget(target);
    }
    async testWebhook(organizationId, targetId, payload, user) {
        var _a, _b, _c, _d;
        await this.ensureOrganizationOwnerAccess(organizationId, user);
        const target = await this.prisma.uptimeTarget.findFirst({
            where: { id: targetId, organizationId },
            include: TARGET_WITH_CONTEXT_INCLUDE
        });
        if (!target) {
            throw new common_1.NotFoundException('Uptime target not found.');
        }
        const webhookUrl = (_d = (_b = (_a = payload.webhookUrl) !== null && _a !== void 0 ? _a : target.alertWebhookUrl) !== null && _b !== void 0 ? _b : (_c = target.project) === null || _c === void 0 ? void 0 : _c.uptimeWebhookUrl) !== null && _d !== void 0 ? _d : target.organization.uptimeWebhookUrl;
        if (!webhookUrl) {
            throw new common_1.BadRequestException('No webhook URL configured for this target or organization.');
        }
        await this.notifier.sendTest(webhookUrl, target.label, {
            state: payload.state,
            reason: payload.reason,
            reasonDetail: payload.reasonDetail
        });
        return { ok: true };
    }
    async runScheduledChecks() {
        const targets = await this.prisma.uptimeTarget.findMany({
            where: { isPaused: false },
            include: TARGET_WITH_CONTEXT_INCLUDE
        });
        const now = Date.now();
        let nextDelayMs = DEFAULT_SCHEDULER_INTERVAL_MS;
        if (targets.length > 0) {
            const nextDueMs = targets.reduce((min, target) => {
                var _a, _b;
                const last = (_b = (_a = target.lastCheckedAt) === null || _a === void 0 ? void 0 : _a.getTime()) !== null && _b !== void 0 ? _b : 0;
                const dueAt = last + target.checkIntervalSeconds * 1000;
                const delta = Math.max(dueAt - now, 0);
                return Math.min(min, delta);
            }, Number.POSITIVE_INFINITY);
            if (Number.isFinite(nextDueMs)) {
                nextDelayMs = Math.max(MIN_SCHEDULER_INTERVAL_MS, nextDueMs);
            }
        }
        for (const target of targets) {
            if (target.lastCheckedAt &&
                now - target.lastCheckedAt.getTime() < target.checkIntervalSeconds * 1000) {
                continue;
            }
            try {
                await this.runProbeForTarget(target);
            }
            catch (error) {
                this.logger.error(`Failed to run uptime check for ${target.url}: ${error.message}`);
            }
        }
        await this.maybeSendDigests();
        return nextDelayMs;
    }
    async runProbeForTarget(target) {
        const probeResult = await this.performCheck(target);
        const previousSnapshot = target.currentSnapshot;
        const { check, snapshot, updatedTarget } = await this.persistProbeResult(target, probeResult);
        if (!previousSnapshot || previousSnapshot.state !== snapshot.state) {
            const previousDurationMs = previousSnapshot
                ? probeResult.checkedAt.getTime() - previousSnapshot.since.getTime()
                : 0;
            await this.notifier.sendStateChange(this.toNotificationTarget(updatedTarget), {
                state: snapshot.state,
                reason: snapshot.reason,
                reasonDetail: snapshot.reasonDetail,
                since: snapshot.since
            }, {
                statusCode: check.statusCode,
                latencyMs: check.latencyMs,
                tlsExpiresAt: check.tlsExpiresAt,
                checkedAt: check.checkedAt
            }, previousDurationMs);
        }
        return { target: updatedTarget, snapshot, check };
    }
    async performCheck(target) {
        var _a;
        const timeoutMs = (_a = target.requestTimeoutMs) !== null && _a !== void 0 ? _a : 5000;
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
            const stateDetail = this.resolveStateFromResponse(statusCode, latencyMs, timeoutMs, target.expectedStatus, tlsExpiresAt);
            return {
                ...stateDetail,
                statusCode,
                latencyMs,
                tlsExpiresAt,
                resolvedAddress,
                checkedAt: new Date()
            };
        }
        catch (error) {
            const latencyMs = Date.now() - startedAt;
            return {
                ...this.mapErrorToState(error, timeoutMs),
                latencyMs,
                checkedAt: new Date()
            };
        }
        finally {
            clearTimeout(timeout);
        }
    }
    resolveStateFromResponse(statusCode, latencyMs, timeoutMs, expectedStatus, tlsExpiresAt) {
        if (statusCode >= 500) {
            return {
                state: client_1.UptimeState.DOWN,
                reason: client_1.UptimeReason.STATUS_CODE,
                reasonDetail: `Received ${statusCode}`
            };
        }
        if (expectedStatus && statusCode !== expectedStatus) {
            return {
                state: client_1.UptimeState.DEGRADED,
                reason: client_1.UptimeReason.STATUS_CODE,
                reasonDetail: `Expected ${expectedStatus}, got ${statusCode}`
            };
        }
        if (statusCode >= 400) {
            return {
                state: client_1.UptimeState.DEGRADED,
                reason: client_1.UptimeReason.STATUS_CODE,
                reasonDetail: `Received ${statusCode}`
            };
        }
        const nearTimeout = latencyMs > timeoutMs * 0.8;
        if (nearTimeout) {
            return {
                state: client_1.UptimeState.DEGRADED,
                reason: client_1.UptimeReason.TIMEOUT,
                reasonDetail: `Slow response (${latencyMs} ms)`
            };
        }
        if (tlsExpiresAt) {
            const daysUntilExpiry = this.daysUntil(tlsExpiresAt);
            if (daysUntilExpiry <= 7) {
                return {
                    state: client_1.UptimeState.DEGRADED,
                    reason: client_1.UptimeReason.TLS,
                    reasonDetail: `TLS expires in ${daysUntilExpiry} day(s)`
                };
            }
        }
        return {
            state: client_1.UptimeState.UP,
            reason: client_1.UptimeReason.STATUS_CODE,
            reasonDetail: 'Server online'
        };
    }
    mapErrorToState(error, timeoutMs) {
        var _a, _b, _c;
        const message = (_a = error.message) !== null && _a !== void 0 ? _a : 'Unknown error';
        if (error.name === 'AbortError') {
            return {
                state: client_1.UptimeState.DOWN,
                reason: client_1.UptimeReason.TIMEOUT,
                reasonDetail: `Timed out after ${timeoutMs} ms`
            };
        }
        const code = (_b = error === null || error === void 0 ? void 0 : error.code) !== null && _b !== void 0 ? _b : (_c = error === null || error === void 0 ? void 0 : error.cause) === null || _c === void 0 ? void 0 : _c.code;
        if (code === 'ENOTFOUND') {
            return { state: client_1.UptimeState.DOWN, reason: client_1.UptimeReason.DNS, reasonDetail: 'DNS resolution failed' };
        }
        if (code === 'ECONNREFUSED' || code === 'ECONNRESET') {
            return { state: client_1.UptimeState.DOWN, reason: client_1.UptimeReason.NETWORK, reasonDetail: 'Connection refused/reset' };
        }
        if (message.toLowerCase().includes('tls')) {
            return { state: client_1.UptimeState.DEGRADED, reason: client_1.UptimeReason.TLS, reasonDetail: message };
        }
        return {
            state: client_1.UptimeState.DOWN,
            reason: client_1.UptimeReason.UNKNOWN,
            reasonDetail: message
        };
    }
    async persistProbeResult(target, result) {
        return this.prisma.$transaction(async (tx) => {
            var _a;
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
            let snapshotId = (_a = target.currentSnapshotId) !== null && _a !== void 0 ? _a : null;
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
            }
            else {
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
                where: { id: snapshotId }
            });
            return { check, snapshot, updatedTarget };
        });
    }
    async maybeSendDigests() {
        var _a;
        const organizations = await this.prisma.organization.findMany({
            where: {
                uptimeWebhookUrl: { not: null },
                uptimeTargets: { some: {} }
            },
            select: { id: true, name: true, uptimeWebhookUrl: true }
        });
        const now = Date.now();
        for (const org of organizations) {
            const lastSent = (_a = this.digestTracker.get(org.id)) !== null && _a !== void 0 ? _a : 0;
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
                .map((target) => {
                var _a, _b, _c, _d, _e, _f;
                return ({
                    label: target.label,
                    url: target.url,
                    state: (_b = (_a = target.currentSnapshot) === null || _a === void 0 ? void 0 : _a.state) !== null && _b !== void 0 ? _b : client_1.UptimeState.UNKNOWN,
                    reason: (_d = (_c = target.currentSnapshot) === null || _c === void 0 ? void 0 : _c.reason) !== null && _d !== void 0 ? _d : client_1.UptimeReason.UNKNOWN,
                    since: (_f = (_e = target.currentSnapshot) === null || _e === void 0 ? void 0 : _e.since) !== null && _f !== void 0 ? _f : new Date()
                });
            });
            if (org.uptimeWebhookUrl) {
                await this.notifier.sendDigest(org.uptimeWebhookUrl, org.name, summaryTargets);
                this.digestTracker.set(org.id, now);
            }
        }
    }
    async resolveAddress(url) {
        try {
            const hostname = new URL(url).hostname;
            const lookup = await dns.lookup(hostname);
            return lookup.address;
        }
        catch {
            return null;
        }
    }
    async resolveTlsExpiry(url) {
        try {
            const parsed = new URL(url);
            if (parsed.protocol !== 'https:') {
                return null;
            }
            return await new Promise((resolve) => {
                const socket = tls.connect({
                    port: parsed.port ? Number.parseInt(parsed.port, 10) : 443,
                    host: parsed.hostname,
                    servername: parsed.hostname,
                    timeout: 4000
                }, () => {
                    const cert = socket.getPeerCertificate();
                    socket.end();
                    if (cert && cert.valid_to) {
                        resolve(new Date(cert.valid_to));
                    }
                    else {
                        resolve(null);
                    }
                });
                socket.on('error', () => resolve(null));
                socket.on('timeout', () => {
                    socket.destroy();
                    resolve(null);
                });
            });
        }
        catch {
            return null;
        }
    }
    normalizeTargetUrl(rawUrl, protocol) {
        let parsed;
        try {
            parsed = new URL(rawUrl);
        }
        catch {
            throw new common_1.BadRequestException('A valid URL is required for uptime monitoring.');
        }
        const scheme = parsed.protocol.replace(':', '').toUpperCase();
        if (scheme !== client_1.UptimeProtocol.HTTP && scheme !== client_1.UptimeProtocol.HTTPS) {
            throw new common_1.BadRequestException('Only HTTP and HTTPS protocols are supported.');
        }
        if (protocol && protocol !== scheme) {
            throw new common_1.BadRequestException('Protocol does not match the provided URL.');
        }
        return { url: parsed.toString(), protocol: scheme };
    }
    daysUntil(date) {
        const diffMs = date.getTime() - Date.now();
        return Math.max(0, Math.ceil(diffMs / (1000 * 60 * 60 * 24)));
    }
    toNotificationTarget(target) {
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
    async ensureTargetInOrganization(organizationId, targetId) {
        const target = await this.prisma.uptimeTarget.findFirst({
            where: { id: targetId, organizationId },
            select: { id: true, protocol: true }
        });
        if (!target) {
            throw new common_1.NotFoundException('Uptime target not found.');
        }
        return target;
    }
    async ensureProjectInOrganization(projectId, organizationId) {
        const project = await this.prisma.project.findFirst({
            where: { id: projectId, organizationId },
            select: { id: true }
        });
        if (!project) {
            throw new common_1.BadRequestException('Project does not belong to this organization.');
        }
    }
    async ensureServerInOrganization(serverId, organizationId) {
        const server = await this.prisma.server.findFirst({
            where: { id: serverId, organizationId },
            select: { id: true }
        });
        if (!server) {
            throw new common_1.BadRequestException('Server does not belong to this organization.');
        }
    }
    async ensureOrganizationReadAccess(organizationId, user) {
        if (user.role === client_1.Role.ADMINISTRATOR) {
            const exists = await this.prisma.organization.findUnique({
                where: { id: organizationId },
                select: { id: true }
            });
            if (!exists) {
                throw new common_1.NotFoundException('Organization not found.');
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
            throw new common_1.ForbiddenException('You do not have access to this organization.');
        }
    }
    async ensureOrganizationOwnerAccess(organizationId, user) {
        if (user.role === client_1.Role.ADMINISTRATOR) {
            const exists = await this.prisma.organization.findUnique({
                where: { id: organizationId },
                select: { id: true }
            });
            if (!exists) {
                throw new common_1.NotFoundException('Organization not found.');
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
        if (!membership || membership.role !== client_1.Role.OWNER) {
            throw new common_1.ForbiddenException('Owner privileges are required for this action.');
        }
    }
    scheduleNextRun(delayMs) {
        if (this.scheduler) {
            clearTimeout(this.scheduler);
        }
        const wait = Math.max(MIN_SCHEDULER_INTERVAL_MS, delayMs !== null && delayMs !== void 0 ? delayMs : DEFAULT_SCHEDULER_INTERVAL_MS);
        this.scheduler = setTimeout(async () => {
            try {
                const nextDelay = await this.runScheduledChecks();
                this.scheduleNextRun(nextDelay);
            }
            catch (error) {
                this.logger.error(`Scheduled uptime run failed: ${error.message}`);
                this.scheduleNextRun();
            }
        }, wait);
    }
};
exports.UptimeService = UptimeService;
exports.UptimeService = UptimeService = UptimeService_1 = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [prisma_service_1.PrismaService,
        uptime_notifier_service_1.UptimeNotifierService])
], UptimeService);
//# sourceMappingURL=uptime.service.js.map