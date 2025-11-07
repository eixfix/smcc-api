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
exports.TaskController = void 0;
const common_1 = require("@nestjs/common");
const create_task_dto_1 = require("./dto/create-task.dto");
const update_task_dto_1 = require("./dto/update-task.dto");
const task_service_1 = require("./task.service");
const current_user_decorator_1 = require("../../common/decorators/current-user.decorator");
let TaskController = class TaskController {
    constructor(taskService) {
        this.taskService = taskService;
    }
    findAll(projectId, user) {
        return this.taskService.findAllByProject(projectId, user);
    }
    create(projectId, payload, user) {
        return this.taskService.create(projectId, payload, user);
    }
    update(taskId, payload, user) {
        return this.taskService.update(taskId, payload, user);
    }
    run(taskId, user) {
        return this.taskService.run(taskId, user);
    }
    findReports(taskId, user) {
        return this.taskService.findReports(taskId, user);
    }
    async exportRecent(user, res) {
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename="load-test-report-${new Date().toISOString().slice(0, 10)}.pdf"`);
        await this.taskService.exportRecentReportsPdf(user, res);
    }
    findRecent(user) {
        return this.taskService.findRecentReports(user);
    }
};
exports.TaskController = TaskController;
__decorate([
    (0, common_1.Get)(),
    __param(0, (0, common_1.Param)('projectId')),
    __param(1, (0, current_user_decorator_1.CurrentUser)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object]),
    __metadata("design:returntype", void 0)
], TaskController.prototype, "findAll", null);
__decorate([
    (0, common_1.Post)(),
    __param(0, (0, common_1.Param)('projectId')),
    __param(1, (0, common_1.Body)()),
    __param(2, (0, current_user_decorator_1.CurrentUser)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, create_task_dto_1.CreateTaskDto, Object]),
    __metadata("design:returntype", void 0)
], TaskController.prototype, "create", null);
__decorate([
    (0, common_1.Put)(':taskId'),
    __param(0, (0, common_1.Param)('taskId')),
    __param(1, (0, common_1.Body)()),
    __param(2, (0, current_user_decorator_1.CurrentUser)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, update_task_dto_1.UpdateTaskDto, Object]),
    __metadata("design:returntype", void 0)
], TaskController.prototype, "update", null);
__decorate([
    (0, common_1.Post)(':taskId/run'),
    __param(0, (0, common_1.Param)('taskId')),
    __param(1, (0, current_user_decorator_1.CurrentUser)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object]),
    __metadata("design:returntype", void 0)
], TaskController.prototype, "run", null);
__decorate([
    (0, common_1.Get)(':taskId/reports'),
    __param(0, (0, common_1.Param)('taskId')),
    __param(1, (0, current_user_decorator_1.CurrentUser)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object]),
    __metadata("design:returntype", void 0)
], TaskController.prototype, "findReports", null);
__decorate([
    (0, common_1.Get)('reports/recent/export'),
    __param(0, (0, current_user_decorator_1.CurrentUser)()),
    __param(1, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, Object]),
    __metadata("design:returntype", Promise)
], TaskController.prototype, "exportRecent", null);
__decorate([
    (0, common_1.Get)('reports/recent'),
    __param(0, (0, current_user_decorator_1.CurrentUser)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object]),
    __metadata("design:returntype", void 0)
], TaskController.prototype, "findRecent", null);
exports.TaskController = TaskController = __decorate([
    (0, common_1.Controller)('projects/:projectId/tasks'),
    __metadata("design:paramtypes", [task_service_1.TaskService])
], TaskController);
//# sourceMappingURL=task.controller.js.map