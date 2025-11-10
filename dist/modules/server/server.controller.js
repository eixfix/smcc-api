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
exports.ServerController = void 0;
const common_1 = require("@nestjs/common");
const client_1 = require("@prisma/client");
const current_user_decorator_1 = require("../../common/decorators/current-user.decorator");
const roles_decorator_1 = require("../../common/decorators/roles.decorator");
const create_server_dto_1 = require("./dto/create-server.dto");
const update_server_dto_1 = require("./dto/update-server.dto");
const server_service_1 = require("./server.service");
let ServerController = class ServerController {
    constructor(serverService) {
        this.serverService = serverService;
    }
    findAll(user, organizationId) {
        return this.serverService.findAll(user, organizationId);
    }
    findOne(id, user) {
        return this.serverService.findOne(id, user);
    }
    create(payload, user) {
        return this.serverService.create(payload, user);
    }
    update(id, payload, user) {
        return this.serverService.update(id, payload, user);
    }
    suspend(id, user) {
        return this.serverService.setSuspension(id, true, user);
    }
    unsuspend(id, user) {
        return this.serverService.setSuspension(id, false, user);
    }
    listTelemetry(id, user, limit) {
        const parsedLimit = limit ? Number.parseInt(limit, 10) : undefined;
        const sanitizedLimit = parsedLimit !== undefined && !Number.isNaN(parsedLimit) ? parsedLimit : undefined;
        return this.serverService.listTelemetry(id, user, sanitizedLimit);
    }
};
exports.ServerController = ServerController;
__decorate([
    (0, common_1.Get)(),
    __param(0, (0, current_user_decorator_1.CurrentUser)()),
    __param(1, (0, common_1.Query)('organizationId')),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, String]),
    __metadata("design:returntype", void 0)
], ServerController.prototype, "findAll", null);
__decorate([
    (0, common_1.Get)(':id'),
    __param(0, (0, common_1.Param)('id')),
    __param(1, (0, current_user_decorator_1.CurrentUser)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object]),
    __metadata("design:returntype", void 0)
], ServerController.prototype, "findOne", null);
__decorate([
    (0, common_1.Post)(),
    (0, roles_decorator_1.Roles)(client_1.Role.ADMINISTRATOR, client_1.Role.OWNER),
    __param(0, (0, common_1.Body)()),
    __param(1, (0, current_user_decorator_1.CurrentUser)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [create_server_dto_1.CreateServerDto, Object]),
    __metadata("design:returntype", void 0)
], ServerController.prototype, "create", null);
__decorate([
    (0, common_1.Patch)(':id'),
    (0, roles_decorator_1.Roles)(client_1.Role.ADMINISTRATOR, client_1.Role.OWNER),
    __param(0, (0, common_1.Param)('id')),
    __param(1, (0, common_1.Body)()),
    __param(2, (0, current_user_decorator_1.CurrentUser)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, update_server_dto_1.UpdateServerDto, Object]),
    __metadata("design:returntype", void 0)
], ServerController.prototype, "update", null);
__decorate([
    (0, common_1.Post)(':id/suspend'),
    (0, roles_decorator_1.Roles)(client_1.Role.ADMINISTRATOR, client_1.Role.OWNER),
    __param(0, (0, common_1.Param)('id')),
    __param(1, (0, current_user_decorator_1.CurrentUser)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object]),
    __metadata("design:returntype", void 0)
], ServerController.prototype, "suspend", null);
__decorate([
    (0, common_1.Post)(':id/unsuspend'),
    (0, roles_decorator_1.Roles)(client_1.Role.ADMINISTRATOR, client_1.Role.OWNER),
    __param(0, (0, common_1.Param)('id')),
    __param(1, (0, current_user_decorator_1.CurrentUser)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object]),
    __metadata("design:returntype", void 0)
], ServerController.prototype, "unsuspend", null);
__decorate([
    (0, common_1.Get)(':id/telemetry'),
    __param(0, (0, common_1.Param)('id')),
    __param(1, (0, current_user_decorator_1.CurrentUser)()),
    __param(2, (0, common_1.Query)('limit')),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object, String]),
    __metadata("design:returntype", void 0)
], ServerController.prototype, "listTelemetry", null);
exports.ServerController = ServerController = __decorate([
    (0, common_1.Controller)('servers'),
    __metadata("design:paramtypes", [server_service_1.ServerService])
], ServerController);
//# sourceMappingURL=server.controller.js.map