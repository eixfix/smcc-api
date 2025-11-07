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
Object.defineProperty(exports, "__esModule", { value: true });
exports.OrganizationCreditService = exports.InsufficientCreditsException = void 0;
const common_1 = require("@nestjs/common");
const prisma_service_1 = require("../../prisma/prisma.service");
const credit_costs_1 = require("../../common/constants/credit-costs");
class InsufficientCreditsException extends common_1.HttpException {
    constructor(required, context) {
        super(context
            ? `Insufficient organization credits to ${context}. Required: ${required} credits.`
            : `Insufficient organization credits. Required: ${required} credits.`, common_1.HttpStatus.PAYMENT_REQUIRED);
    }
}
exports.InsufficientCreditsException = InsufficientCreditsException;
let OrganizationCreditService = class OrganizationCreditService {
    constructor(prisma) {
        this.prisma = prisma;
    }
    async spendCredits(organizationId, amount, tx, context) {
        if (amount <= 0) {
            throw new common_1.BadRequestException('Credit amount must be greater than zero.');
        }
        if (!Number.isInteger(amount)) {
            throw new common_1.BadRequestException('Credit amount must be an integer.');
        }
        const client = this.resolveClient(tx);
        const organization = await client.organization.findUnique({
            where: { id: organizationId },
            select: { credits: true }
        });
        if (!organization) {
            throw new common_1.NotFoundException('Organization not found.');
        }
        if (organization.credits < amount) {
            throw new InsufficientCreditsException(amount, context);
        }
        const now = new Date();
        await client.organization.update({
            where: { id: organizationId },
            data: {
                credits: {
                    decrement: amount
                },
                lastDebitAt: now
            }
        });
    }
    async addCredits(organizationId, amount, tx) {
        if (amount <= 0) {
            throw new common_1.BadRequestException('Credit amount must be greater than zero.');
        }
        if (!Number.isInteger(amount)) {
            throw new common_1.BadRequestException('Credit amount must be an integer.');
        }
        const client = this.resolveClient(tx);
        const now = new Date();
        const updated = await client.organization.update({
            where: { id: organizationId },
            data: {
                credits: {
                    increment: amount
                },
                lastCreditedAt: now
            },
            select: { credits: true, scanSuspendedAt: true }
        });
        if (updated.credits > 0 && updated.scanSuspendedAt) {
            await client.organization.update({
                where: { id: organizationId },
                data: {
                    scanSuspendedAt: null
                }
            });
        }
        return Number(updated.credits);
    }
    async refundCredits(organizationId, amount) {
        await this.addCredits(organizationId, amount);
    }
    resolveClient(tx) {
        return tx !== null && tx !== void 0 ? tx : this.prisma;
    }
    async debitForServerScan(organizationId, tx) {
        await this.spendCredits(organizationId, credit_costs_1.CREDIT_COST_SERVER_SCAN, tx, 'queue a server scan');
    }
    async debitForTelemetry(organizationId, tx) {
        await this.spendCredits(organizationId, credit_costs_1.CREDIT_COST_SERVER_TELEMETRY, tx, 'record server telemetry');
    }
};
exports.OrganizationCreditService = OrganizationCreditService;
exports.OrganizationCreditService = OrganizationCreditService = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [prisma_service_1.PrismaService])
], OrganizationCreditService);
//# sourceMappingURL=organization-credit.service.js.map