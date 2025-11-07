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
exports.ProjectService = void 0;
const common_1 = require("@nestjs/common");
const client_1 = require("@prisma/client");
const credit_costs_1 = require("../../common/constants/credit-costs");
const prisma_service_1 = require("../../prisma/prisma.service");
const organization_credit_service_1 = require("../organization/organization-credit.service");
let ProjectService = class ProjectService {
    constructor(prisma, creditService) {
        this.prisma = prisma;
        this.creditService = creditService;
    }
    async findAllByOrganization(organizationId, user) {
        await this.verifyOrganizationAccess(organizationId, user);
        return this.prisma.project.findMany({
            where: { organizationId },
            orderBy: { createdAt: 'desc' }
        });
    }
    async create(organizationId, payload, user) {
        await this.verifyOrganizationAccess(organizationId, user);
        return this.prisma.$transaction(async (tx) => {
            await this.creditService.spendCredits(organizationId, credit_costs_1.CREDIT_COST_CREATE_PROJECT, tx, 'create a project');
            return tx.project.create({
                data: {
                    name: payload.name,
                    description: payload.description,
                    organizationId
                }
            });
        });
    }
    async update(id, payload, user) {
        const project = await this.prisma.project.findUnique({
            where: { id },
            select: { organizationId: true }
        });
        if (!project) {
            throw new common_1.NotFoundException('Project not found.');
        }
        await this.verifyOrganizationAccess(project.organizationId, user);
        return this.prisma.project.update({
            where: { id },
            data: payload
        });
    }
    async verifyOrganizationAccess(organizationId, user) {
        if (user.role === client_1.Role.ADMINISTRATOR) {
            const exists = await this.prisma.organization.findUnique({
                where: { id: organizationId },
                select: { id: true }
            });
            if (!exists) {
                throw new common_1.NotFoundException('Organization not found.');
            }
            return;
        }
        const membership = await this.prisma.organizationMember.findFirst({
            where: {
                organizationId,
                userId: user.userId
            },
            select: { id: true }
        });
        if (!membership) {
            const exists = await this.prisma.organization.findUnique({
                where: { id: organizationId },
                select: { id: true }
            });
            if (!exists) {
                throw new common_1.NotFoundException('Organization not found.');
            }
            throw new common_1.ForbiddenException('You do not have access to this organization.');
        }
    }
};
exports.ProjectService = ProjectService;
exports.ProjectService = ProjectService = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [prisma_service_1.PrismaService,
        organization_credit_service_1.OrganizationCreditService])
], ProjectService);
//# sourceMappingURL=project.service.js.map