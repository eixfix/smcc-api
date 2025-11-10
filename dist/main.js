"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const common_1 = require("@nestjs/common");
const core_1 = require("@nestjs/core");
const helmet_1 = require("helmet");
const app_module_1 = require("./modules/app/app.module");
async function bootstrap() {
    var _a, _b, _c;
    const app = await core_1.NestFactory.create(app_module_1.AppModule);
    const debugFlag = ((_a = process.env.APP_DEBUG) !== null && _a !== void 0 ? _a : '').trim().toLowerCase();
    const enableDebugLogs = debugFlag === 'true' || debugFlag === '1' || debugFlag === 'yes';
    if (enableDebugLogs) {
        const debugLogLevels = ['error', 'warn', 'log', 'debug', 'verbose'];
        app.useLogger(debugLogLevels);
        common_1.Logger.log('API debug logging enabled', 'Bootstrap');
    }
    const corsOrigins = ((_b = process.env.CORS_ORIGINS) !== null && _b !== void 0 ? _b : 'http://localhost:3000')
        .split(',')
        .map((origin) => origin.trim())
        .filter(Boolean);
    app.enableCors({
        origin: corsOrigins,
        credentials: true
    });
    app.use((0, helmet_1.default)({
        crossOriginResourcePolicy: { policy: 'same-site' }
    }));
    app.useGlobalPipes(new common_1.ValidationPipe({
        whitelist: true,
        transform: true
    }));
    await app.listen((_c = process.env.PORT) !== null && _c !== void 0 ? _c : 3001);
}
void bootstrap();
//# sourceMappingURL=main.js.map