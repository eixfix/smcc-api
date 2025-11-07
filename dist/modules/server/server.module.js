"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ServerModule = void 0;
const common_1 = require("@nestjs/common");
const config_1 = require("@nestjs/config");
const jwt_1 = require("@nestjs/jwt");
const organization_module_1 = require("../organization/organization.module");
const agent_session_guard_1 = require("./guards/agent-session.guard");
const server_agent_controller_1 = require("./server-agent.controller");
const server_agent_service_1 = require("./server-agent.service");
const server_controller_1 = require("./server.controller");
const server_scan_controller_1 = require("./server-scan.controller");
const server_scan_service_1 = require("./server-scan.service");
const server_service_1 = require("./server.service");
let ServerModule = class ServerModule {
};
exports.ServerModule = ServerModule;
exports.ServerModule = ServerModule = __decorate([
    (0, common_1.Module)({
        imports: [
            config_1.ConfigModule,
            jwt_1.JwtModule.registerAsync({
                imports: [config_1.ConfigModule],
                inject: [config_1.ConfigService],
                useFactory: (configService) => ({
                    secret: configService.get('JWT_SECRET'),
                    signOptions: {
                        expiresIn: '15m'
                    }
                })
            }),
            organization_module_1.OrganizationModule
        ],
        controllers: [server_controller_1.ServerController, server_agent_controller_1.ServerAgentController, server_scan_controller_1.ServerScanController],
        providers: [server_service_1.ServerService, server_agent_service_1.ServerAgentService, server_scan_service_1.ServerScanService, agent_session_guard_1.AgentSessionGuard]
    })
], ServerModule);
//# sourceMappingURL=server.module.js.map