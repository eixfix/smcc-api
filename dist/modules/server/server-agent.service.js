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
const config_1 = require("@nestjs/config");
const jwt_1 = require("@nestjs/jwt");
const client_1 = require("@prisma/client");
const bcrypt = require("bcryptjs");
const crypto_1 = require("crypto");
const prisma_service_1 = require("../../prisma/prisma.service");
const ip_utils_1 = require("../../common/utils/ip.utils");
const server_service_1 = require("./server.service");
const credit_costs_1 = require("../../common/constants/credit-costs");
const SECRET_TOKEN_BYTE_LENGTH = 32;
const AGENT_SESSION_TTL_SECONDS = 15 * 60;
const DEFAULT_POLL_INTERVAL_SECONDS = 30;
const DEFAULT_TELEMETRY_INTERVAL_MINUTES = 30;
const DEFAULT_UPDATE_INTERVAL_MINUTES = 60;
const DEFAULT_CONFIG_REFRESH_MINUTES = 360;
let ServerAgentService = class ServerAgentService {
    constructor(prisma, serverService, jwtService, configService) {
        this.prisma = prisma;
        this.serverService = serverService;
        this.jwtService = jwtService;
        this.configService = configService;
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
        const capabilities = Array.isArray(dto.capabilities)
            ? dto.capabilities.filter((flag) => typeof flag === 'string')
            : [];
        const capabilitySet = new Set(capabilities);
        if (!capabilitySet.has('envelope_v1')) {
            throw new common_1.UnauthorizedException('Agents must support envelope_v1.');
        }
        if (!capabilitySet.has('config_v1') || !capabilitySet.has('update_v1')) {
            throw new common_1.UnauthorizedException('Agents must advertise config_v1 and update_v1 capabilities.');
        }
        const envelopeKey = (0, crypto_1.randomBytes)(32);
        const sessionToken = await this.jwtService.signAsync({
            sub: agent.id,
            serverId: agent.serverId,
            organizationId: agent.server.organizationId,
            type: 'agent-session',
            envelope: envelopeKey.toString('base64'),
            envelopeVersion: 'v1',
            capabilities: Array.from(capabilitySet)
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
            envelope: {
                version: 'v1',
                key: envelopeKey.toString('base64')
            },
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
    getRemoteConfig(agent) {
        var _a;
        const issuedAt = new Date().toISOString();
        const version = (_a = this.configService.get('AGENT_CONFIG_VERSION')) !== null && _a !== void 0 ? _a : '1.0.0';
        const payload = {
            version,
            issuedAt,
            serverId: agent.serverId,
            settings: {
                apiUrl: this.getApiUrl(),
                pollIntervalSeconds: this.getNumericEnv('AGENT_CONFIG_POLL_INTERVAL_SECONDS', DEFAULT_POLL_INTERVAL_SECONDS),
                telemetryIntervalMinutes: this.getNumericEnv('AGENT_CONFIG_TELEMETRY_INTERVAL_MINUTES', DEFAULT_TELEMETRY_INTERVAL_MINUTES),
                updateIntervalMinutes: this.getNumericEnv('AGENT_CONFIG_UPDATE_INTERVAL_MINUTES', DEFAULT_UPDATE_INTERVAL_MINUTES),
                refreshIntervalMinutes: this.getNumericEnv('AGENT_CONFIG_REFRESH_INTERVAL_MINUTES', DEFAULT_CONFIG_REFRESH_MINUTES),
                featureFlags: this.getFeatureFlags(),
                credits: {
                    scan: credit_costs_1.CREDIT_COST_SERVER_SCAN,
                    telemetry: credit_costs_1.CREDIT_COST_SERVER_TELEMETRY
                }
            }
        };
        return {
            ...payload,
            signature: this.signPayload(payload, true)
        };
    }
    async publishUpdateManifest(dto, user) {
        var _a, _b, _c, _d, _e, _f, _g, _h;
        this.ensureAdministrator(user);
        const downloadUrl = ((_a = dto.downloadUrl) === null || _a === void 0 ? void 0 : _a.trim()) || null;
        const inlineSource = ((_b = dto.inlineSourceB64) === null || _b === void 0 ? void 0 : _b.trim()) || null;
        const checksumValue = ((_c = dto.checksumValue) === null || _c === void 0 ? void 0 : _c.trim()) || null;
        const checksumAlgorithm = checksumValue !== null
            ? ((_d = dto.checksumAlgorithm) === null || _d === void 0 ? void 0 : _d.trim()) || 'sha256'
            : null;
        const record = await this.prisma.agentUpdateManifest.create({
            data: {
                version: dto.version.trim(),
                channel: dto.channel.trim(),
                downloadUrl,
                inlineSourceB64: inlineSource,
                checksumAlgorithm,
                checksumValue,
                restartRequired: (_e = dto.restartRequired) !== null && _e !== void 0 ? _e : true,
                minConfigVersion: ((_f = dto.minConfigVersion) === null || _f === void 0 ? void 0 : _f.trim()) || null,
                notes: ((_g = dto.notes) === null || _g === void 0 ? void 0 : _g.trim()) || null,
                createdById: (_h = user.userId) !== null && _h !== void 0 ? _h : null
            },
            include: {
                createdBy: {
                    select: {
                        id: true,
                        email: true,
                        name: true
                    }
                }
            }
        });
        return this.mapManifestForAdmin(record);
    }
    async listUpdateManifests(user, limit) {
        this.ensureAdministrator(user);
        const take = Math.min(Math.max(limit !== null && limit !== void 0 ? limit : 20, 1), 100);
        const records = await this.prisma.agentUpdateManifest.findMany({
            orderBy: { createdAt: 'desc' },
            take,
            include: {
                createdBy: {
                    select: {
                        id: true,
                        email: true,
                        name: true
                    }
                }
            }
        });
        return records.map((record) => this.mapManifestForAdmin(record));
    }
    async getUpdateManifest(agent, currentVersion) {
        var _a, _b, _c, _d, _e;
        const record = await this.prisma.agentUpdateManifest.findFirst({
            orderBy: { createdAt: 'desc' }
        });
        if (record) {
            if (currentVersion && record.version === currentVersion) {
                return null;
            }
            const payload = this.buildManifestPayload({
                version: record.version,
                channel: record.channel,
                issuedAt: record.createdAt.toISOString(),
                serverId: agent.serverId,
                minConfigVersion: (_a = record.minConfigVersion) !== null && _a !== void 0 ? _a : this.getDefaultConfigVersion(),
                downloadUrl: (_b = record.downloadUrl) !== null && _b !== void 0 ? _b : null,
                inlineSourceB64: (_c = record.inlineSourceB64) !== null && _c !== void 0 ? _c : null,
                checksumAlgorithm: (_d = record.checksumAlgorithm) !== null && _d !== void 0 ? _d : undefined,
                checksumValue: (_e = record.checksumValue) !== null && _e !== void 0 ? _e : undefined,
                restartRequired: record.restartRequired,
                currentVersion: currentVersion !== null && currentVersion !== void 0 ? currentVersion : null
            });
            return {
                ...payload,
                signature: this.signPayload(payload, false)
            };
        }
        const legacyManifest = this.buildLegacyUpdateManifest(agent, currentVersion);
        if (!legacyManifest) {
            return null;
        }
        return {
            ...legacyManifest,
            signature: this.signPayload(legacyManifest, false)
        };
    }
    getApiUrl() {
        var _a;
        const url = (_a = this.configService.get('API_PUBLIC_URL')) !== null && _a !== void 0 ? _a : '';
        return url.replace(/\/$/, '');
    }
    getDefaultConfigVersion() {
        var _a;
        return (_a = this.configService.get('AGENT_CONFIG_VERSION')) !== null && _a !== void 0 ? _a : '1.0.0';
    }
    buildLegacyUpdateManifest(agent, currentVersion) {
        var _a, _b, _c, _d, _e;
        const version = (_a = this.configService.get('AGENT_UPDATE_VERSION')) !== null && _a !== void 0 ? _a : this.configService.get('AGENT_SCRIPT_VERSION');
        const downloadUrl = (_b = this.configService.get('AGENT_UPDATE_DOWNLOAD_URL')) !== null && _b !== void 0 ? _b : null;
        const inlineSource = (_c = this.configService.get('AGENT_UPDATE_EMBEDDED_SOURCE_B64')) !== null && _c !== void 0 ? _c : null;
        if (!version || (!downloadUrl && !inlineSource)) {
            return null;
        }
        const checksum = (_d = this.configService.get('AGENT_UPDATE_CHECKSUM')) !== null && _d !== void 0 ? _d : null;
        return this.buildManifestPayload({
            version,
            channel: (_e = this.configService.get('AGENT_UPDATE_CHANNEL')) !== null && _e !== void 0 ? _e : 'stable',
            issuedAt: new Date().toISOString(),
            serverId: agent.serverId,
            minConfigVersion: this.getDefaultConfigVersion(),
            downloadUrl,
            inlineSourceB64: inlineSource,
            checksumAlgorithm: checksum ? 'sha256' : undefined,
            checksumValue: checksum !== null && checksum !== void 0 ? checksum : undefined,
            restartRequired: true,
            currentVersion: currentVersion !== null && currentVersion !== void 0 ? currentVersion : null
        });
    }
    getNumericEnv(key, fallback) {
        const raw = this.configService.get(key);
        const parsed = raw !== undefined ? Number(raw) : Number.NaN;
        return Number.isFinite(parsed) ? parsed : fallback;
    }
    buildManifestPayload(options) {
        var _a, _b;
        const checksum = options.checksumValue !== undefined && options.checksumValue !== null
            ? {
                algorithm: (_a = options.checksumAlgorithm) !== null && _a !== void 0 ? _a : 'sha256',
                value: options.checksumValue
            }
            : null;
        const inlineSource = options.inlineSourceB64 && options.inlineSourceB64.length > 0
            ? {
                encoding: 'base64',
                data: options.inlineSourceB64
            }
            : null;
        return {
            version: options.version,
            channel: options.channel,
            issuedAt: options.issuedAt,
            serverId: options.serverId,
            minConfigVersion: options.minConfigVersion,
            downloadUrl: options.downloadUrl,
            checksum,
            inlineSource,
            restartRequired: (_b = options.restartRequired) !== null && _b !== void 0 ? _b : true,
            currentVersion: options.currentVersion
        };
    }
    mapManifestForAdmin(record) {
        var _a;
        return {
            id: record.id,
            version: record.version,
            channel: record.channel,
            downloadUrl: record.downloadUrl,
            hasInlineSource: Boolean(record.inlineSourceB64),
            checksum: record.checksumValue
                ? {
                    algorithm: (_a = record.checksumAlgorithm) !== null && _a !== void 0 ? _a : 'sha256',
                    value: record.checksumValue
                }
                : null,
            restartRequired: record.restartRequired,
            minConfigVersion: record.minConfigVersion,
            notes: record.notes,
            createdAt: record.createdAt.toISOString(),
            createdBy: record.createdBy
                ? {
                    id: record.createdBy.id,
                    email: record.createdBy.email,
                    name: record.createdBy.name
                }
                : null
        };
    }
    getFeatureFlags() {
        const rawFlags = this.configService.get('AGENT_FEATURE_FLAGS_JSON');
        if (!rawFlags) {
            return {};
        }
        try {
            const parsed = JSON.parse(rawFlags);
            if (this.isRecord(parsed)) {
                return Object.entries(parsed).reduce((acc, [key, value]) => {
                    acc[key] = Boolean(value);
                    return acc;
                }, {});
            }
        }
        catch {
            return {};
        }
        return {};
    }
    signPayload(payload, isConfig) {
        const key = isConfig ? this.getConfigSignatureKey() : this.getUpdateSignatureKey();
        try {
            return (0, crypto_1.createHmac)('sha256', key)
                .update(JSON.stringify(payload))
                .digest('base64');
        }
        catch (error) {
            throw new common_1.InternalServerErrorException('Unable to sign agent payload.');
        }
    }
    getConfigSignatureKey() {
        var _a;
        const raw = (_a = this.configService.get('AGENT_CONFIG_SIGNATURE_KEY')) !== null && _a !== void 0 ? _a : this.configService.get('AGENT_PAYLOAD_KEY');
        if (!raw) {
            throw new common_1.InternalServerErrorException('AGENT_CONFIG_SIGNATURE_KEY is not configured.');
        }
        return this.toKeyBuffer(raw);
    }
    getUpdateSignatureKey() {
        var _a, _b;
        const raw = (_b = (_a = this.configService.get('AGENT_UPDATE_SIGNATURE_KEY')) !== null && _a !== void 0 ? _a : this.configService.get('AGENT_CONFIG_SIGNATURE_KEY')) !== null && _b !== void 0 ? _b : this.configService.get('AGENT_PAYLOAD_KEY');
        if (!raw) {
            throw new common_1.InternalServerErrorException('AGENT_UPDATE_SIGNATURE_KEY is not configured.');
        }
        return this.toKeyBuffer(raw);
    }
    toKeyBuffer(value) {
        try {
            return Buffer.from(value, /^[A-Za-z0-9+/=]+$/.test(value) ? 'base64' : 'utf8');
        }
        catch {
            return Buffer.from(value, 'utf8');
        }
    }
    isRecord(value) {
        return typeof value === 'object' && value !== null && !Array.isArray(value);
    }
    ensureAdministrator(user) {
        if (user.role !== client_1.Role.ADMINISTRATOR) {
            throw new common_1.ForbiddenException('Administrator privileges are required for this operation.');
        }
    }
};
exports.ServerAgentService = ServerAgentService;
exports.ServerAgentService = ServerAgentService = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [prisma_service_1.PrismaService,
        server_service_1.ServerService,
        jwt_1.JwtService,
        config_1.ConfigService])
], ServerAgentService);
//# sourceMappingURL=server-agent.service.js.map