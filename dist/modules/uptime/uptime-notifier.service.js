"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var UptimeNotifierService_1;
Object.defineProperty(exports, "__esModule", { value: true });
exports.UptimeNotifierService = void 0;
const common_1 = require("@nestjs/common");
const client_1 = require("@prisma/client");
let UptimeNotifierService = UptimeNotifierService_1 = class UptimeNotifierService {
    constructor() {
        this.logger = new common_1.Logger(UptimeNotifierService_1.name);
    }
    async sendStateChange(target, snapshot, check, previousStateDurationMs) {
        var _a;
        const webhookUrl = this.resolveWebhook(target);
        if (!webhookUrl) {
            return;
        }
        const payload = {
            content: `⚠️ Uptime update for ${target.label}`,
            embeds: [
                {
                    title: `${snapshot.state} – ${target.url}`,
                    description: (_a = snapshot.reasonDetail) !== null && _a !== void 0 ? _a : snapshot.reason,
                    color: this.resolveStateColor(snapshot.state),
                    fields: [
                        { name: 'State', value: snapshot.state, inline: true },
                        snapshot.reasonDetail
                            ? { name: 'Detail', value: snapshot.reasonDetail, inline: true }
                            : null,
                        {
                            name: 'Latency',
                            value: check.latencyMs ? `${check.latencyMs} ms` : 'n/a',
                            inline: true
                        },
                        {
                            name: 'Status Code',
                            value: check.statusCode ? check.statusCode.toString() : 'n/a',
                            inline: true
                        },
                        {
                            name: 'Duration In Previous State',
                            value: this.formatDuration(previousStateDurationMs),
                            inline: true
                        },
                        {
                            name: 'Sensitivity',
                            value: target.sensitivity,
                            inline: true
                        }
                    ].filter(Boolean),
                    footer: {
                        text: `${target.organization.name}${target.project ? ` · ${target.project.name}` : ''}${target.region ? ` · ${target.region}` : ''}`
                    },
                    timestamp: check.checkedAt.toISOString()
                }
            ]
        };
        await this.sendWebhook(webhookUrl, payload, 'state-change');
    }
    async sendDigest(webhookUrl, organizationName, targets) {
        var _a, _b, _c;
        if (!targets.length) {
            return;
        }
        const counts = targets.reduce((acc, target) => {
            var _a;
            acc[target.state] = ((_a = acc[target.state]) !== null && _a !== void 0 ? _a : 0) + 1;
            return acc;
        }, {});
        const lines = targets.slice(0, 20).map((target) => {
            var _a;
            const duration = this.formatDuration(Date.now() - target.since.getTime());
            const reasonText = (_a = target.reasonDetail) !== null && _a !== void 0 ? _a : target.reason;
            return `• ${target.label} – ${target.state} (${duration}, ${reasonText})`;
        });
        const payload = {
            content: `🧭 Uptime digest for ${organizationName}`,
            embeds: [
                {
                    title: 'Domain summary',
                    description: lines.join('\n'),
                    fields: [
                        { name: 'UP', value: String((_a = counts[client_1.UptimeState.UP]) !== null && _a !== void 0 ? _a : 0), inline: true },
                        { name: 'DEGRADED', value: String((_b = counts[client_1.UptimeState.DEGRADED]) !== null && _b !== void 0 ? _b : 0), inline: true },
                        { name: 'DOWN', value: String((_c = counts[client_1.UptimeState.DOWN]) !== null && _c !== void 0 ? _c : 0), inline: true }
                    ],
                    color: 5763719,
                    timestamp: new Date().toISOString()
                }
            ]
        };
        await this.sendWebhook(webhookUrl, payload, 'digest');
    }
    async sendTest(webhookUrl, label, payload) {
        var _a, _b, _c, _d;
        const content = {
            content: `🔧 Uptime webhook test for ${label}`,
            embeds: [
                {
                    title: `${(_a = payload.state) !== null && _a !== void 0 ? _a : client_1.UptimeState.UP} – ${(_b = payload.reason) !== null && _b !== void 0 ? _b : client_1.UptimeReason.UNKNOWN}`,
                    description: (_c = payload.reasonDetail) !== null && _c !== void 0 ? _c : 'Webhook test triggered from dashboard',
                    color: this.resolveStateColor((_d = payload.state) !== null && _d !== void 0 ? _d : client_1.UptimeState.UP),
                    timestamp: new Date().toISOString()
                }
            ]
        };
        await this.sendWebhook(webhookUrl, content, 'test');
    }
    resolveWebhook(target) {
        var _a, _b, _c, _d;
        return ((_d = (_c = (_a = target.alertWebhookUrl) !== null && _a !== void 0 ? _a : (_b = target.project) === null || _b === void 0 ? void 0 : _b.uptimeWebhookUrl) !== null && _c !== void 0 ? _c : target.organization.uptimeWebhookUrl) !== null && _d !== void 0 ? _d : null);
    }
    resolveStateColor(state) {
        switch (state) {
            case client_1.UptimeState.UP:
                return 5793266;
            case client_1.UptimeState.DEGRADED:
                return 16763904;
            case client_1.UptimeState.DOWN:
                return 15548997;
            default:
                return 7506394;
        }
    }
    formatDuration(durationMs) {
        if (!durationMs || durationMs < 1000) {
            return 'just now';
        }
        const seconds = Math.floor(durationMs / 1000);
        const minutes = Math.floor(seconds / 60);
        const hours = Math.floor(minutes / 60);
        const days = Math.floor(hours / 24);
        if (days > 0) {
            return `${days}d ${hours % 24}h`;
        }
        if (hours > 0) {
            return `${hours}h ${minutes % 60}m`;
        }
        if (minutes > 0) {
            return `${minutes}m ${seconds % 60}s`;
        }
        return `${seconds}s`;
    }
    async sendWebhook(url, payload, type) {
        try {
            const response = await fetch(url, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(payload)
            });
            if (!response.ok) {
                this.logger.warn(`Failed to send ${type} webhook to ${url}: ${response.statusText}`);
            }
        }
        catch (error) {
            this.logger.error(`Error sending ${type} webhook to ${url}: ${error.message}`);
        }
    }
};
exports.UptimeNotifierService = UptimeNotifierService;
exports.UptimeNotifierService = UptimeNotifierService = UptimeNotifierService_1 = __decorate([
    (0, common_1.Injectable)()
], UptimeNotifierService);
//# sourceMappingURL=uptime-notifier.service.js.map