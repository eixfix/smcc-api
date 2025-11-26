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
exports.UptimeController = void 0;
const common_1 = require("@nestjs/common");
const client_1 = require("@prisma/client");
const current_user_decorator_1 = require("../../common/decorators/current-user.decorator");
const roles_decorator_1 = require("../../common/decorators/roles.decorator");
const create_uptime_target_dto_1 = require("./dto/create-uptime-target.dto");
const test_webhook_dto_1 = require("./dto/test-webhook.dto");
const update_uptime_target_dto_1 = require("./dto/update-uptime-target.dto");
const uptime_service_1 = require("./uptime.service");
let UptimeController = class UptimeController {
    constructor(uptimeService) {
        this.uptimeService = uptimeService;
    }
    listTargets(organizationId, user) {
        return this.uptimeService.listTargets(organizationId, user);
    }
    createTarget(organizationId, payload, user) {
        return this.uptimeService.createTarget(organizationId, payload, user);
    }
    getTarget(organizationId, targetId, user) {
        return this.uptimeService.getTarget(organizationId, targetId, user);
    }
    updateTarget(organizationId, targetId, payload, user) {
        return this.uptimeService.updateTarget(organizationId, targetId, payload, user);
    }
    listChecks(organizationId, targetId, limit, user) {
        const parsedLimit = limit ? Number.parseInt(limit, 10) : undefined;
        const safeLimit = parsedLimit && !Number.isNaN(parsedLimit) ? parsedLimit : undefined;
        return this.uptimeService.listChecks(organizationId, targetId, user, safeLimit);
    }
    runCheck(organizationId, targetId, user) {
        return this.uptimeService.runCheckNow(organizationId, targetId, user);
    }
    testWebhook(organizationId, targetId, payload, user) {
        return this.uptimeService.testWebhook(organizationId, targetId, payload, user);
    }
};
exports.UptimeController = UptimeController;
__decorate([
    (0, common_1.Get)('targets'),
    __param(0, (0, common_1.Param)('organizationId')),
    __param(1, (0, current_user_decorator_1.CurrentUser)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object]),
    __metadata("design:returntype", void 0)
], UptimeController.prototype, "listTargets", null);
__decorate([
    (0, common_1.Post)('targets'),
    (0, roles_decorator_1.Roles)(client_1.Role.ADMINISTRATOR, client_1.Role.OWNER),
    __param(0, (0, common_1.Param)('organizationId')),
    __param(1, (0, common_1.Body)()),
    __param(2, (0, current_user_decorator_1.CurrentUser)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, create_uptime_target_dto_1.CreateUptimeTargetDto, Object]),
    __metadata("design:returntype", void 0)
], UptimeController.prototype, "createTarget", null);
__decorate([
    (0, common_1.Get)('targets/:targetId'),
    __param(0, (0, common_1.Param)('organizationId')),
    __param(1, (0, common_1.Param)('targetId')),
    __param(2, (0, current_user_decorator_1.CurrentUser)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, String, Object]),
    __metadata("design:returntype", void 0)
], UptimeController.prototype, "getTarget", null);
__decorate([
    (0, common_1.Patch)('targets/:targetId'),
    (0, roles_decorator_1.Roles)(client_1.Role.ADMINISTRATOR, client_1.Role.OWNER),
    __param(0, (0, common_1.Param)('organizationId')),
    __param(1, (0, common_1.Param)('targetId')),
    __param(2, (0, common_1.Body)()),
    __param(3, (0, current_user_decorator_1.CurrentUser)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, String, update_uptime_target_dto_1.UpdateUptimeTargetDto, Object]),
    __metadata("design:returntype", void 0)
], UptimeController.prototype, "updateTarget", null);
__decorate([
    (0, common_1.Get)('targets/:targetId/checks'),
    __param(0, (0, common_1.Param)('organizationId')),
    __param(1, (0, common_1.Param)('targetId')),
    __param(2, (0, common_1.Query)('limit')),
    __param(3, (0, current_user_decorator_1.CurrentUser)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, String, Object, Object]),
    __metadata("design:returntype", void 0)
], UptimeController.prototype, "listChecks", null);
__decorate([
    (0, common_1.Post)('targets/:targetId/run'),
    __param(0, (0, common_1.Param)('organizationId')),
    __param(1, (0, common_1.Param)('targetId')),
    __param(2, (0, current_user_decorator_1.CurrentUser)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, String, Object]),
    __metadata("design:returntype", void 0)
], UptimeController.prototype, "runCheck", null);
__decorate([
    (0, common_1.Post)('targets/:targetId/test-webhook'),
    (0, roles_decorator_1.Roles)(client_1.Role.ADMINISTRATOR, client_1.Role.OWNER),
    __param(0, (0, common_1.Param)('organizationId')),
    __param(1, (0, common_1.Param)('targetId')),
    __param(2, (0, common_1.Body)()),
    __param(3, (0, current_user_decorator_1.CurrentUser)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, String, test_webhook_dto_1.TestWebhookDto, Object]),
    __metadata("design:returntype", void 0)
], UptimeController.prototype, "testWebhook", null);
exports.UptimeController = UptimeController = __decorate([
    (0, common_1.Controller)('organizations/:organizationId/uptime'),
    __metadata("design:paramtypes", [uptime_service_1.UptimeService])
], UptimeController);
//# sourceMappingURL=uptime.controller.js.map