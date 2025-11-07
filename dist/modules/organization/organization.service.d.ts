import type { Organization } from '@prisma/client';
import { Role } from '@prisma/client';
import { PrismaService } from '../../prisma/prisma.service';
import type { AuthenticatedUser } from '../../common/types/auth-user';
import { CreateOrganizationDto } from './dto/create-organization.dto';
import { UpdateOrganizationDto } from './dto/update-organization.dto';
import { OrganizationCreditService } from './organization-credit.service';
export declare class OrganizationService {
    private readonly prisma;
    private readonly creditService;
    constructor(prisma: PrismaService, creditService: OrganizationCreditService);
    findAll(user: AuthenticatedUser): Promise<(Organization & {
        _count: {
            projects: number;
        };
    })[]>;
    findOne(id: string, user: AuthenticatedUser): Promise<Organization | null>;
    create(payload: CreateOrganizationDto): Promise<Organization & {
        owner: {
            id: string;
            name: string;
            email: string;
            role: Role;
        } | null;
        _count: {
            projects: number;
        };
    }>;
    update(id: string, payload: UpdateOrganizationDto): Promise<Organization>;
    addCredits(id: string, amount: number): Promise<{
        credits: number;
    }>;
}
//# sourceMappingURL=organization.service.d.ts.map