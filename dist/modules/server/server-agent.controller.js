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
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ServerAgentController = void 0;
const common_1 = require("@nestjs/common");
const client_1 = require("@prisma/client");
const public_decorator_1 = require("../../common/decorators/public.decorator");
const current_user_decorator_1 = require("../../common/decorators/current-user.decorator");
const roles_decorator_1 = require("../../common/decorators/roles.decorator");
const current_agent_decorator_1 = require("./decorators/current-agent.decorator");
const agent_auth_dto_1 = require("./dto/agent-auth.dto");
const create_server_agent_dto_1 = require("./dto/create-server-agent.dto");
const create_agent_update_manifest_dto_1 = require("./dto/create-agent-update-manifest.dto");
const agent_session_guard_1 = require("./guards/agent-session.guard");
const agent_envelope_interceptor_1 = require("./interceptors/agent-envelope.interceptor");
const server_agent_service_1 = require("./server-agent.service");
const ip_utils_1 = require("../../common/utils/ip.utils");
let ServerAgentController = class ServerAgentController {
    constructor(serverAgentService) {
        this.serverAgentService = serverAgentService;
    }
    createAgent(serverId, payload, user) {
        return this.serverAgentService.mintAgentToken(serverId, payload, user);
    }
    revokeAgent(agentId, user) {
        return this.serverAgentService.revokeAgent(agentId, user);
    }
    authenticate(payload, request) {
        const clientIp = (0, ip_utils_1.extractClientIp)(request);
        return this.serverAgentService.authenticateAgent(payload, clientIp);
    }
    fetchConfig(request, agent) {
        this.assertCapability(request, 'config_v1');
        if (!agent) {
            throw new common_1.ForbiddenException('Agent session missing from request context.');
        }
        return this.serverAgentService.getRemoteConfig(agent);
    }
    fetchUpdateManifest(request, agent, currentVersion) {
        this.assertCapability(request, 'update_v1');
        if (!agent) {
            throw new common_1.ForbiddenException('Agent session missing from request context.');
        }
        return this.serverAgentService.getUpdateManifest(agent, currentVersion);
    }
    publishUpdateManifest(payload, user) {
        return this.serverAgentService.publishUpdateManifest(payload, user);
    }
    listUpdateManifests(user, limit) {
        const parsed = limit ? Number.parseInt(limit, 10) : undefined;
        const sanitized = parsed !== undefined && !Number.isNaN(parsed) ? parsed : undefined;
        return this.serverAgentService.listUpdateManifests(user, sanitized);
    }
    assertCapability(request, capability) {
        var _a;
        const capabilities = (_a = request.agentCapabilities) !== null && _a !== void 0 ? _a : [];
        if (!capabilities.includes(capability)) {
            throw new common_1.ForbiddenException(`Agent is missing required capability: ${capability}`);
        }
    }
};
exports.ServerAgentController = ServerAgentController;
__decorate([
    (0, common_1.Post)('servers/:serverId/agents'),
    (0, roles_decorator_1.Roles)(client_1.Role.ADMINISTRATOR, client_1.Role.OWNER),
    __param(0, (0, common_1.Param)('serverId')),
    __param(1, (0, common_1.Body)()),
    __param(2, (0, current_user_decorator_1.CurrentUser)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, create_server_agent_dto_1.CreateServerAgentDto, Object]),
    __metadata("design:returntype", void 0)
], ServerAgentController.prototype, "createAgent", null);
__decorate([
    (0, common_1.Post)('servers/:serverId/agents/:agentId/revoke'),
    (0, roles_decorator_1.Roles)(client_1.Role.ADMINISTRATOR, client_1.Role.OWNER),
    __param(0, (0, common_1.Param)('agentId')),
    __param(1, (0, current_user_decorator_1.CurrentUser)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object]),
    __metadata("design:returntype", void 0)
], ServerAgentController.prototype, "revokeAgent", null);
__decorate([
    (0, public_decorator_1.Public)(),
    (0, common_1.Post)('agent/auth'),
    __param(0, (0, common_1.Body)()),
    __param(1, (0, common_1.Req)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [agent_auth_dto_1.AgentAuthDto, Object]),
    __metadata("design:returntype", void 0)
], ServerAgentController.prototype, "authenticate", null);
__decorate([
    (0, public_decorator_1.Public)(),
    (0, common_1.Get)('agent/config'),
    (0, common_1.UseGuards)(agent_session_guard_1.AgentSessionGuard),
    (0, common_1.UseInterceptors)(agent_envelope_interceptor_1.AgentEnvelopeInterceptor),
    __param(0, (0, common_1.Req)()),
    __param(1, (0, current_agent_decorator_1.CurrentAgent)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, Object]),
    __metadata("design:returntype", void 0)
], ServerAgentController.prototype, "fetchConfig", null);
__decorate([
    (0, public_decorator_1.Public)(),
    (0, common_1.Get)('agent/update'),
    (0, common_1.UseGuards)(agent_session_guard_1.AgentSessionGuard),
    (0, common_1.UseInterceptors)(agent_envelope_interceptor_1.AgentEnvelopeInterceptor),
    __param(0, (0, common_1.Req)()),
    __param(1, (0, current_agent_decorator_1.CurrentAgent)()),
    __param(2, (0, common_1.Query)('currentVersion')),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, Object, String]),
    __metadata("design:returntype", void 0)
], ServerAgentController.prototype, "fetchUpdateManifest", null);
__decorate([
    (0, roles_decorator_1.Roles)(client_1.Role.ADMINISTRATOR),
    (0, common_1.Post)('agents/update/manifest'),
    __param(0, (0, common_1.Body)()),
    __param(1, (0, current_user_decorator_1.CurrentUser)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [create_agent_update_manifest_dto_1.CreateAgentUpdateManifestDto, Object]),
    __metadata("design:returntype", void 0)
], ServerAgentController.prototype, "publishUpdateManifest", null);
__decorate([
    (0, roles_decorator_1.Roles)(client_1.Role.ADMINISTRATOR),
    (0, common_1.Get)('agents/update/manifests'),
    __param(0, (0, current_user_decorator_1.CurrentUser)()),
    __param(1, (0, common_1.Query)('limit')),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, String]),
    __metadata("design:returntype", void 0)
], ServerAgentController.prototype, "listUpdateManifests", null);
exports.ServerAgentController = ServerAgentController = __decorate([
    (0, common_1.Controller)(),
    __metadata("design:paramtypes", [server_agent_service_1.ServerAgentService])
], ServerAgentController);
//# sourceMappingURL=server-agent.controller.js.map