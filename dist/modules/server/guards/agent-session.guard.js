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
exports.AgentSessionGuard = void 0;
const common_1 = require("@nestjs/common");
const config_1 = require("@nestjs/config");
const jwt_1 = require("@nestjs/jwt");
const prisma_service_1 = require("../../../prisma/prisma.service");
const ip_utils_1 = require("../../../common/utils/ip.utils");
let AgentSessionGuard = class AgentSessionGuard {
    constructor(jwtService, configService, prisma) {
        this.jwtService = jwtService;
        this.configService = configService;
        this.prisma = prisma;
    }
    async canActivate(context) {
        var _a;
        const request = context.switchToHttp().getRequest();
        const authorization = (_a = request.headers.authorization) !== null && _a !== void 0 ? _a : '';
        if (!authorization || typeof authorization !== 'string') {
            throw new common_1.UnauthorizedException('Missing agent session token.');
        }
        const [scheme, token] = authorization.split(' ');
        if (!token || scheme.toLowerCase() !== 'bearer') {
            throw new common_1.UnauthorizedException('Invalid agent authorization header.');
        }
        try {
            const secret = this.configService.get('JWT_SECRET');
            const payload = await this.jwtService.verifyAsync(token, {
                secret
            });
            if (payload.type !== 'agent-session') {
                throw new common_1.UnauthorizedException('Invalid agent session token type.');
            }
            const clientIp = (0, ip_utils_1.extractClientIp)(request);
            await this.assertAllowedIp(payload.sub, payload.serverId, clientIp);
            request.agent = {
                agentId: payload.sub,
                serverId: payload.serverId,
                organizationId: payload.organizationId
            };
            return true;
        }
        catch (error) {
            throw new common_1.UnauthorizedException('Invalid or expired agent session token.');
        }
    }
    async assertAllowedIp(agentId, serverId, clientIp) {
        const agent = await this.prisma.serverAgent.findUnique({
            where: { id: agentId },
            select: {
                serverId: true,
                server: {
                    select: {
                        allowedIp: true
                    }
                }
            }
        });
        if (!agent || agent.serverId !== serverId) {
            throw new common_1.UnauthorizedException('Agent session is no longer valid.');
        }
        const allowedIp = (0, ip_utils_1.normalizeIp)(agent.server.allowedIp);
        if (!allowedIp) {
            return;
        }
        const normalizedClientIp = (0, ip_utils_1.normalizeIp)(clientIp);
        if (!normalizedClientIp || normalizedClientIp !== allowedIp) {
            throw new common_1.UnauthorizedException('Agent IP is not authorized for this server.');
        }
    }
};
exports.AgentSessionGuard = AgentSessionGuard;
exports.AgentSessionGuard = AgentSessionGuard = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [jwt_1.JwtService,
        config_1.ConfigService,
        prisma_service_1.PrismaService])
], AgentSessionGuard);
//# sourceMappingURL=agent-session.guard.js.map