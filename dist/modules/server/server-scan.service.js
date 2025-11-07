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
Object.defineProperty(exports, "__esModule", { value: true });
exports.ServerScanService = void 0;
const common_1 = require("@nestjs/common");
const client_1 = require("@prisma/client");
const credit_costs_1 = require("../../common/constants/credit-costs");
const prisma_service_1 = require("../../prisma/prisma.service");
const organization_credit_service_1 = require("../organization/organization-credit.service");
const server_agent_service_1 = require("./server-agent.service");
const server_service_1 = require("./server.service");
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
};
let ServerScanService = class ServerScanService {
    constructor(prisma, creditService, serverService, serverAgentService) {
        this.prisma = prisma;
        this.creditService = creditService;
        this.serverService = serverService;
        this.serverAgentService = serverAgentService;
    }
    async queueScan(serverId, dto, user) {
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
            throw new common_1.NotFoundException('Server not found.');
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
                        ? dto.parameters
                        : undefined,
                    status: client_1.ServerScanStatus.QUEUED,
                    creditsCharged: credit_costs_1.CREDIT_COST_SERVER_SCAN
                },
                select: SCAN_WITH_RESULT_SELECT
            });
        });
    }
    async listScans(serverId, user) {
        await this.serverService.ensureServerOwnerAccess(serverId, user);
        return this.prisma.serverScan.findMany({
            where: { serverId },
            orderBy: { queuedAt: 'desc' },
            select: SCAN_WITH_RESULT_SELECT
        });
    }
    async getNextQueuedScan(agent) {
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
            throw new common_1.NotFoundException('Server not found.');
        }
        this.assertScanningAllowed(server.isSuspended, server.organization.scanSuspendedAt);
        const job = await this.prisma.$transaction(async (tx) => {
            const pending = await tx.serverScan.findFirst({
                where: {
                    serverId: agent.serverId,
                    status: client_1.ServerScanStatus.QUEUED
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
                    status: client_1.ServerScanStatus.QUEUED
                },
                data: {
                    status: client_1.ServerScanStatus.RUNNING,
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
    async submitScanReport(agent, scanId, dto) {
        if (dto.status !== client_1.ServerScanStatus.COMPLETED &&
            dto.status !== client_1.ServerScanStatus.FAILED) {
            throw new common_1.ForbiddenException('Invalid scan status update.');
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
            throw new common_1.NotFoundException('Scan not found for this server.');
        }
        if (scan.status === client_1.ServerScanStatus.COMPLETED ||
            scan.status === client_1.ServerScanStatus.FAILED ||
            scan.status === client_1.ServerScanStatus.TIMED_OUT) {
            throw new common_1.ForbiddenException('Scan has already been finalized.');
        }
        if (scan.agentId && scan.agentId !== agent.agentId) {
            throw new common_1.ForbiddenException('Scan is assigned to a different agent.');
        }
        const now = new Date();
        await this.prisma.$transaction(async (tx) => {
            var _a;
            await tx.serverScan.update({
                where: { id: scanId },
                data: {
                    status: dto.status,
                    completedAt: now,
                    failureReason: dto.status === client_1.ServerScanStatus.FAILED ? (_a = dto.failureReason) !== null && _a !== void 0 ? _a : 'Unknown failure' : null,
                    agentId: agent.agentId
                }
            });
            await tx.serverScanResult.upsert({
                where: { scanId },
                create: {
                    scanId,
                    summaryJson: dto.summary
                        ? dto.summary
                        : undefined,
                    rawLog: dto.rawLog,
                    storageMetricsJson: dto.storageMetrics
                        ? dto.storageMetrics
                        : undefined,
                    memoryMetricsJson: dto.memoryMetrics
                        ? dto.memoryMetrics
                        : undefined,
                    securityFindingsJson: dto.securityFindings
                        ? dto.securityFindings
                        : undefined
                },
                update: {
                    summaryJson: dto.summary
                        ? dto.summary
                        : undefined,
                    rawLog: dto.rawLog,
                    storageMetricsJson: dto.storageMetrics
                        ? dto.storageMetrics
                        : undefined,
                    memoryMetricsJson: dto.memoryMetrics
                        ? dto.memoryMetrics
                        : undefined,
                    securityFindingsJson: dto.securityFindings
                        ? dto.securityFindings
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
    async ingestTelemetry(agent, dto) {
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
            throw new common_1.NotFoundException('Server not found.');
        }
        this.assertScanningAllowed(server.isSuspended, server.organization.scanSuspendedAt);
        const record = await this.prisma.$transaction(async (tx) => {
            var _a, _b, _c;
            await this.creditService.debitForTelemetry(server.organizationId, tx);
            return tx.serverTelemetry.create({
                data: {
                    serverId: agent.serverId,
                    agentId: agent.agentId,
                    cpuPercent: (_a = dto.cpuPercent) !== null && _a !== void 0 ? _a : null,
                    memoryPercent: (_b = dto.memoryPercent) !== null && _b !== void 0 ? _b : null,
                    diskPercent: (_c = dto.diskPercent) !== null && _c !== void 0 ? _c : null,
                    rawJson: dto.raw ? dto.raw : undefined,
                    creditsCharged: credit_costs_1.CREDIT_COST_SERVER_TELEMETRY
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
    assertScanningAllowed(serverSuspended, scanSuspendedAt) {
        if (serverSuspended) {
            throw new common_1.ForbiddenException('Server scanning is suspended.');
        }
        if (scanSuspendedAt) {
            throw new common_1.ForbiddenException('Organization scanning is suspended.');
        }
    }
};
exports.ServerScanService = ServerScanService;
exports.ServerScanService = ServerScanService = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [prisma_service_1.PrismaService,
        organization_credit_service_1.OrganizationCreditService,
        server_service_1.ServerService,
        server_agent_service_1.ServerAgentService])
], ServerScanService);
//# sourceMappingURL=server-scan.service.js.map