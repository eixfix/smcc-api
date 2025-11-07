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
exports.OrganizationService = void 0;
const common_1 = require("@nestjs/common");
const client_1 = require("@prisma/client");
const bcrypt = require("bcryptjs");
const prisma_service_1 = require("../../prisma/prisma.service");
const organization_credit_service_1 = require("./organization-credit.service");
let OrganizationService = class OrganizationService {
    constructor(prisma, creditService) {
        this.prisma = prisma;
        this.creditService = creditService;
    }
    findAll(user) {
        const where = user.role === client_1.Role.ADMINISTRATOR
            ? {}
            : {
                members: {
                    some: {
                        userId: user.userId
                    }
                }
            };
        return this.prisma.organization.findMany({
            where,
            orderBy: { createdAt: 'desc' },
            include: {
                _count: {
                    select: {
                        projects: true
                    }
                }
            }
        });
    }
    async findOne(id, user) {
        const organization = await this.prisma.organization.findUnique({ where: { id } });
        if (!organization) {
            return null;
        }
        if (user.role === client_1.Role.ADMINISTRATOR) {
            return organization;
        }
        const membership = await this.prisma.organizationMember.findFirst({
            where: {
                organizationId: id,
                userId: user.userId
            }
        });
        if (!membership) {
            throw new common_1.ForbiddenException('You do not have access to this organization.');
        }
        return organization;
    }
    async create(payload) {
        const passwordHash = await bcrypt.hash(payload.owner.password, 10);
        return this.prisma.$transaction(async (tx) => {
            const owner = await tx.user.create({
                data: {
                    email: payload.owner.email,
                    name: payload.owner.name,
                    passwordHash,
                    role: client_1.Role.OWNER
                },
                select: {
                    id: true,
                    name: true,
                    email: true,
                    role: true
                }
            });
            const organization = await tx.organization.create({
                data: {
                    name: payload.name,
                    slug: payload.slug,
                    ownerId: owner.id,
                    members: {
                        create: {
                            userId: owner.id,
                            role: client_1.Role.OWNER
                        }
                    }
                },
                include: {
                    owner: {
                        select: {
                            id: true,
                            name: true,
                            email: true,
                            role: true
                        }
                    },
                    _count: {
                        select: {
                            projects: true
                        }
                    }
                }
            });
            return organization;
        });
    }
    update(id, payload) {
        return this.prisma.organization.update({
            where: { id },
            data: payload
        });
    }
    async addCredits(id, amount) {
        const credits = await this.creditService.addCredits(id, amount);
        return { credits };
    }
};
exports.OrganizationService = OrganizationService;
exports.OrganizationService = OrganizationService = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [prisma_service_1.PrismaService,
        organization_credit_service_1.OrganizationCreditService])
], OrganizationService);
//# sourceMappingURL=organization.service.js.map