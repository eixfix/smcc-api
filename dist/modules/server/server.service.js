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
exports.ServerService = void 0;
const common_1 = require("@nestjs/common");
const client_1 = require("@prisma/client");
const prisma_service_1 = require("../../prisma/prisma.service");
const ip_utils_1 = require("../../common/utils/ip.utils");
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
};
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
};
let ServerService = class ServerService {
    constructor(prisma) {
        this.prisma = prisma;
    }
    async create(payload, user) {
        await this.ensureOrganizationOwnerAccess(payload.organizationId, user);
        const allowedIp = (0, ip_utils_1.normalizeIp)(payload.allowedIp);
        if (!allowedIp) {
            throw new common_1.BadRequestException('A valid server IP address is required.');
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
    async findAll(user, organizationId) {
        const where = {};
        if (user.role === client_1.Role.ADMINISTRATOR) {
            if (organizationId) {
                const exists = await this.prisma.organization.findUnique({
                    where: { id: organizationId },
                    select: { id: true }
                });
                if (!exists) {
                    throw new common_1.NotFoundException('Organization not found.');
                }
                where.organizationId = organizationId;
            }
        }
        else {
            const accessibleOrganizationIds = await this.listUserOrganizationIds(user.userId);
            if (organizationId) {
                await this.ensureOrganizationReadAccess(organizationId, user);
                where.organizationId = organizationId;
            }
            else {
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
    async findOne(id, user) {
        const server = await this.prisma.server.findUnique({
            where: { id },
            select: SERVER_DETAIL_SELECT
        });
        if (!server) {
            throw new common_1.NotFoundException('Server not found.');
        }
        await this.ensureOrganizationReadAccess(server.organization.id, user);
        return server;
    }
    async update(id, payload, user) {
        const summary = await this.prisma.server.findUnique({
            where: { id },
            select: { id: true, organizationId: true }
        });
        if (!summary) {
            throw new common_1.NotFoundException('Server not found.');
        }
        if (payload.isSuspended !== undefined) {
            await this.ensureOrganizationOwnerAccess(summary.organizationId, user);
        }
        else {
            await this.ensureOrganizationReadAccess(summary.organizationId, user);
        }
        const allowedIp = payload.allowedIp !== undefined ? (0, ip_utils_1.normalizeIp)(payload.allowedIp) : undefined;
        if (payload.allowedIp !== undefined && !allowedIp) {
            throw new common_1.BadRequestException('A valid server IP address is required.');
        }
        return this.prisma.server.update({
            where: { id },
            data: {
                name: payload.name,
                hostname: payload.hostname,
                description: payload.description,
                allowedIp,
                isSuspended: payload.isSuspended !== undefined ? payload.isSuspended : undefined
            },
            select: SERVER_DETAIL_SELECT
        });
    }
    async setSuspension(id, isSuspended, user) {
        const server = await this.prisma.server.findUnique({
            where: { id },
            select: { id: true, organizationId: true }
        });
        if (!server) {
            throw new common_1.NotFoundException('Server not found.');
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
    async ensureServerOwnerAccess(serverId, user) {
        const server = await this.prisma.server.findUnique({
            where: { id: serverId },
            select: { id: true, organizationId: true }
        });
        if (!server) {
            throw new common_1.NotFoundException('Server not found.');
        }
        await this.ensureOrganizationOwnerAccess(server.organizationId, user);
        return server;
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
        if (!membership) {
            throw new common_1.ForbiddenException('You do not have access to this organization.');
        }
        if (membership.role !== client_1.Role.OWNER) {
            throw new common_1.ForbiddenException('Owner privileges are required for this action.');
        }
    }
    async listUserOrganizationIds(userId) {
        const memberships = await this.prisma.organizationMember.findMany({
            where: { userId },
            select: { organizationId: true }
        });
        return memberships.map((membership) => membership.organizationId);
    }
};
exports.ServerService = ServerService;
exports.ServerService = ServerService = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [prisma_service_1.PrismaService])
], ServerService);
//# sourceMappingURL=server.service.js.map