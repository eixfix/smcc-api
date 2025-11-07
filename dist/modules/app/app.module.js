"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.AppModule = void 0;
const common_1 = require("@nestjs/common");
const config_1 = require("@nestjs/config");
const core_1 = require("@nestjs/core");
const throttler_1 = require("@nestjs/throttler");
const prisma_module_1 = require("../../prisma/prisma.module");
const jwt_auth_guard_1 = require("../../common/guards/jwt-auth.guard");
const roles_guard_1 = require("../../common/guards/roles.guard");
const analytics_module_1 = require("../analytics/analytics.module");
const auth_module_1 = require("../auth/auth.module");
const organization_module_1 = require("../organization/organization.module");
const project_module_1 = require("../project/project.module");
const security_module_1 = require("../security/security.module");
const task_module_1 = require("../task/task.module");
const server_module_1 = require("../server/server.module");
const app_controller_1 = require("./app.controller");
const app_service_1 = require("./app.service");
let AppModule = class AppModule {
};
exports.AppModule = AppModule;
exports.AppModule = AppModule = __decorate([
    (0, common_1.Module)({
        imports: [
            config_1.ConfigModule.forRoot({
                isGlobal: true
            }),
            throttler_1.ThrottlerModule.forRoot([
                {
                    ttl: 60,
                    limit: 100
                }
            ]),
            prisma_module_1.PrismaModule,
            auth_module_1.AuthModule,
            analytics_module_1.AnalyticsModule,
            organization_module_1.OrganizationModule,
            project_module_1.ProjectModule,
            task_module_1.TaskModule,
            security_module_1.SecurityModule,
            server_module_1.ServerModule
        ],
        controllers: [app_controller_1.AppController],
        providers: [
            app_service_1.AppService,
            {
                provide: core_1.APP_GUARD,
                useClass: throttler_1.ThrottlerGuard
            },
            {
                provide: core_1.APP_GUARD,
                useClass: jwt_auth_guard_1.JwtAuthGuard
            },
            {
                provide: core_1.APP_GUARD,
                useClass: roles_guard_1.RolesGuard
            }
        ]
    })
], AppModule);
//# sourceMappingURL=app.module.js.map