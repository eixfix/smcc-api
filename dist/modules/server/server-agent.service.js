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
exports.ServerAgentService = void 0;
const common_1 = require("@nestjs/common");
const jwt_1 = require("@nestjs/jwt");
const client_1 = require("@prisma/client");
const bcrypt = require("bcryptjs");
const crypto_1 = require("crypto");
const prisma_service_1 = require("../../prisma/prisma.service");
const ip_utils_1 = require("../../common/utils/ip.utils");
const server_service_1 = require("./server.service");
const SECRET_TOKEN_BYTE_LENGTH = 32;
const AGENT_SESSION_TTL_SECONDS = 15 * 60;
let ServerAgentService = class ServerAgentService {
    constructor(prisma, serverService, jwtService) {
        this.prisma = prisma;
        this.serverService = serverService;
        this.jwtService = jwtService;
    }
    async mintAgentToken(serverId, dto, user) {
        await this.serverService.ensureServerOwnerAccess(serverId, user);
        const accessKey = this.generateAccessKey();
        const secretToken = (0, crypto_1.randomBytes)(SECRET_TOKEN_BYTE_LENGTH).toString('hex');
        const hashedSecret = await bcrypt.hash(secretToken, 12);
        const agent = await this.prisma.$transaction(async (tx) => {
            await tx.serverAgent.updateMany({
                where: {
                    serverId,
                    status: client_1.ServerAgentStatus.ACTIVE
                },
                data: {
                    status: client_1.ServerAgentStatus.REVOKED
                }
            });
            return tx.serverAgent.create({
                data: {
                    serverId,
                    accessKey,
                    hashedSecret,
                    issuedById: user.userId,
                    expiresAt: dto.expiresAt ? new Date(dto.expiresAt) : null
                },
                select: {
                    id: true,
                    serverId: true,
                    issuedAt: true,
                    expiresAt: true,
                    status: true,
                    accessKey: true
                }
            });
        });
        return {
            agent,
            credentials: {
                accessKey,
                secret: secretToken
            }
        };
    }
    async revokeAgent(agentId, user) {
        const agent = await this.prisma.serverAgent.findUnique({
            where: { id: agentId },
            select: {
                id: true,
                status: true,
                server: {
                    select: {
                        id: true,
                        organizationId: true
                    }
                }
            }
        });
        if (!agent) {
            throw new common_1.ForbiddenException('Agent not found or access denied.');
        }
        await this.serverService.ensureOrganizationOwnerAccess(agent.server.organizationId, user);
        return this.prisma.serverAgent.update({
            where: { id: agentId },
            data: {
                status: client_1.ServerAgentStatus.REVOKED
            },
            select: {
                id: true,
                status: true,
                lastSeenAt: true
            }
        });
    }
    async authenticateAgent(dto, clientIp) {
        const agent = await this.prisma.serverAgent.findFirst({
            where: {
                serverId: dto.serverId,
                accessKey: dto.accessKey
            },
            select: {
                id: true,
                hashedSecret: true,
                accessKey: true,
                expiresAt: true,
                status: true,
                serverId: true,
                server: {
                    select: {
                        id: true,
                        name: true,
                        allowedIp: true,
                        isSuspended: true,
                        organizationId: true,
                        organization: {
                            select: {
                                id: true,
                                name: true,
                                credits: true,
                                scanSuspendedAt: true
                            }
                        }
                    }
                }
            }
        });
        if (!agent) {
            throw new common_1.UnauthorizedException('Invalid agent credentials.');
        }
        if (agent.status !== client_1.ServerAgentStatus.ACTIVE) {
            throw new common_1.UnauthorizedException('Agent token is no longer active.');
        }
        if (agent.expiresAt && agent.expiresAt.getTime() < Date.now()) {
            await this.prisma.serverAgent.update({
                where: { id: agent.id },
                data: { status: client_1.ServerAgentStatus.EXPIRED }
            });
            throw new common_1.UnauthorizedException('Agent token has expired.');
        }
        const normalizedClientIp = (0, ip_utils_1.normalizeIp)(clientIp);
        const allowedIp = (0, ip_utils_1.normalizeIp)(agent.server.allowedIp);
        if (allowedIp && normalizedClientIp !== allowedIp) {
            throw new common_1.UnauthorizedException('Agent IP is not authorized for this server.');
        }
        if (agent.server.isSuspended) {
            throw new common_1.ForbiddenException('Server scanning is suspended for this host.');
        }
        if (agent.server.organization.scanSuspendedAt) {
            throw new common_1.ForbiddenException('Organization scanning is currently suspended.');
        }
        const isValid = await bcrypt.compare(dto.secret, agent.hashedSecret);
        if (!isValid) {
            throw new common_1.UnauthorizedException('Invalid agent credentials.');
        }
        const sessionToken = await this.jwtService.signAsync({
            sub: agent.id,
            serverId: agent.serverId,
            organizationId: agent.server.organizationId,
            type: 'agent-session'
        });
        const now = new Date();
        await this.prisma.serverAgent.update({
            where: { id: agent.id },
            data: {
                lastSeenAt: now
            }
        });
        return {
            sessionToken,
            expiresInSeconds: AGENT_SESSION_TTL_SECONDS,
            agent: {
                id: agent.id,
                serverId: agent.serverId,
                status: agent.status,
                lastSeenAt: now,
                expiresAt: agent.expiresAt
            },
            server: {
                id: agent.server.id,
                name: agent.server.name,
                isSuspended: agent.server.isSuspended
            },
            organization: {
                id: agent.server.organization.id,
                name: agent.server.organization.name,
                credits: agent.server.organization.credits,
                scanSuspendedAt: agent.server.organization.scanSuspendedAt
            }
        };
    }
    async touchAgentHeartbeat(agentContext) {
        await this.prisma.serverAgent.update({
            where: { id: agentContext.agentId },
            data: {
                lastSeenAt: new Date()
            }
        });
    }
    generateAccessKey() {
        const random = (0, crypto_1.randomBytes)(12).toString('base64url');
        return `agt_${random}`;
    }
};
exports.ServerAgentService = ServerAgentService;
exports.ServerAgentService = ServerAgentService = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [prisma_service_1.PrismaService,
        server_service_1.ServerService,
        jwt_1.JwtService])
], ServerAgentService);
//# sourceMappingURL=server-agent.service.js.map