"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.AgentEnvelopeInterceptor = void 0;
const common_1 = require("@nestjs/common");
const node_crypto_1 = require("node:crypto");
const operators_1 = require("rxjs/operators");
let AgentEnvelopeInterceptor = class AgentEnvelopeInterceptor {
    intercept(context, next) {
        const http = context.switchToHttp();
        const request = http.getRequest();
        const response = http.getResponse();
        const envelope = request.agentEnvelope;
        if (!envelope || envelope.version !== 'v1') {
            return next.handle();
        }
        return next.handle().pipe((0, operators_1.map)((data) => {
            if (response.statusCode === 204 || data === undefined) {
                return data;
            }
            const payload = this.encrypt(envelope.key, data);
            response.setHeader('x-agent-envelope', 'v1');
            return payload;
        }));
    }
    encrypt(key, data) {
        const iv = (0, node_crypto_1.randomBytes)(12);
        const cipher = (0, node_crypto_1.createCipheriv)('aes-256-gcm', key, iv);
        const ciphertext = Buffer.concat([
            cipher.update(Buffer.from(JSON.stringify(data), 'utf8')),
            cipher.final()
        ]);
        const tag = cipher.getAuthTag();
        return {
            ciphertext: ciphertext.toString('base64'),
            iv: iv.toString('base64'),
            tag: tag.toString('base64')
        };
    }
};
exports.AgentEnvelopeInterceptor = AgentEnvelopeInterceptor;
exports.AgentEnvelopeInterceptor = AgentEnvelopeInterceptor = __decorate([
    (0, common_1.Injectable)()
], AgentEnvelopeInterceptor);
//# sourceMappingURL=agent-envelope.interceptor.js.map