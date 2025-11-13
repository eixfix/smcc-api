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
exports.ServerScanController = void 0;
const common_1 = require("@nestjs/common");
const client_1 = require("@prisma/client");
const public_decorator_1 = require("../../common/decorators/public.decorator");
const current_user_decorator_1 = require("../../common/decorators/current-user.decorator");
const roles_decorator_1 = require("../../common/decorators/roles.decorator");
const current_agent_decorator_1 = require("./decorators/current-agent.decorator");
const queue_server_scan_dto_1 = require("./dto/queue-server-scan.dto");
const report_server_scan_dto_1 = require("./dto/report-server-scan.dto");
const telemetry_payload_dto_1 = require("./dto/telemetry-payload.dto");
const agent_session_guard_1 = require("./guards/agent-session.guard");
const server_scan_service_1 = require("./server-scan.service");
const agent_envelope_interceptor_1 = require("./interceptors/agent-envelope.interceptor");
let ServerScanController = class ServerScanController {
    constructor(serverScanService) {
        this.serverScanService = serverScanService;
    }
    queueScan(serverId, payload, user) {
        return this.serverScanService.queueScan(serverId, payload, user);
    }
    listAllScans(user, limit) {
        const parsedLimit = limit ? Number.parseInt(limit, 10) : undefined;
        const sanitizedLimit = parsedLimit !== undefined && !Number.isNaN(parsedLimit) ? parsedLimit : undefined;
        return this.serverScanService.listRecentScans(user, sanitizedLimit);
    }
    listScans(serverId, user) {
        return this.serverScanService.listScans(serverId, user);
    }
    fetchNext(agent) {
        return this.serverScanService.getNextQueuedScan(agent);
    }
    submitReport(scanId, payload, agent) {
        return this.serverScanService.submitScanReport(agent, scanId, payload);
    }
    ingestTelemetry(payload, agent) {
        return this.serverScanService.ingestTelemetry(agent, payload);
    }
};
exports.ServerScanController = ServerScanController;
__decorate([
    (0, common_1.Post)('servers/:serverId/scans'),
    (0, roles_decorator_1.Roles)(client_1.Role.ADMINISTRATOR, client_1.Role.OWNER),
    __param(0, (0, common_1.Param)('serverId')),
    __param(1, (0, common_1.Body)()),
    __param(2, (0, current_user_decorator_1.CurrentUser)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, queue_server_scan_dto_1.QueueServerScanDto, Object]),
    __metadata("design:returntype", void 0)
], ServerScanController.prototype, "queueScan", null);
__decorate([
    (0, common_1.Get)('servers/scans'),
    (0, roles_decorator_1.Roles)(client_1.Role.ADMINISTRATOR, client_1.Role.OWNER),
    __param(0, (0, current_user_decorator_1.CurrentUser)()),
    __param(1, (0, common_1.Query)('limit')),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, String]),
    __metadata("design:returntype", void 0)
], ServerScanController.prototype, "listAllScans", null);
__decorate([
    (0, common_1.Get)('servers/:serverId/scans'),
    (0, roles_decorator_1.Roles)(client_1.Role.ADMINISTRATOR, client_1.Role.OWNER),
    __param(0, (0, common_1.Param)('serverId')),
    __param(1, (0, current_user_decorator_1.CurrentUser)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object]),
    __metadata("design:returntype", void 0)
], ServerScanController.prototype, "listScans", null);
__decorate([
    (0, public_decorator_1.Public)(),
    (0, common_1.UseGuards)(agent_session_guard_1.AgentSessionGuard),
    (0, common_1.UseInterceptors)(agent_envelope_interceptor_1.AgentEnvelopeInterceptor),
    (0, common_1.Post)('agent/scans/next'),
    __param(0, (0, current_agent_decorator_1.CurrentAgent)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object]),
    __metadata("design:returntype", void 0)
], ServerScanController.prototype, "fetchNext", null);
__decorate([
    (0, public_decorator_1.Public)(),
    (0, common_1.UseGuards)(agent_session_guard_1.AgentSessionGuard),
    (0, common_1.UseInterceptors)(agent_envelope_interceptor_1.AgentEnvelopeInterceptor),
    (0, common_1.Post)('agent/scans/:scanId/report'),
    __param(0, (0, common_1.Param)('scanId')),
    __param(1, (0, common_1.Body)()),
    __param(2, (0, current_agent_decorator_1.CurrentAgent)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, report_server_scan_dto_1.ReportServerScanDto, Object]),
    __metadata("design:returntype", void 0)
], ServerScanController.prototype, "submitReport", null);
__decorate([
    (0, public_decorator_1.Public)(),
    (0, common_1.UseGuards)(agent_session_guard_1.AgentSessionGuard),
    (0, common_1.UseInterceptors)(agent_envelope_interceptor_1.AgentEnvelopeInterceptor),
    (0, common_1.Post)('agent/telemetry'),
    __param(0, (0, common_1.Body)()),
    __param(1, (0, current_agent_decorator_1.CurrentAgent)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [telemetry_payload_dto_1.TelemetryPayloadDto, Object]),
    __metadata("design:returntype", void 0)
], ServerScanController.prototype, "ingestTelemetry", null);
exports.ServerScanController = ServerScanController = __decorate([
    (0, common_1.Controller)(),
    __metadata("design:paramtypes", [server_scan_service_1.ServerScanService])
], ServerScanController);
//# sourceMappingURL=server-scan.controller.js.map