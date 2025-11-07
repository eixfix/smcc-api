import { Role } from '@prisma/client';
import { CreateOrganizationDto } from './dto/create-organization.dto';
import { UpdateOrganizationDto } from './dto/update-organization.dto';
import { UpdateOrganizationCreditsDto } from './dto/update-organization-credits.dto';
import { OrganizationService } from './organization.service';
import type { AuthenticatedUser } from '../../common/types/auth-user';
export declare class OrganizationController {
    private readonly organizationService;
    constructor(organizationService: OrganizationService);
    findAll(user: AuthenticatedUser): Promise<({
        id: string;
        createdAt: Date;
        updatedAt: Date;
        name: string;
        slug: string;
        credits: number;
        lastCreditedAt: Date;
        lastDebitAt: Date | null;
        scanSuspendedAt: Date | null;
        ownerId: string | null;
    } & {
        _count: {
            projects: number;
        };
    })[]>;
    findOne(id: string, user: AuthenticatedUser): Promise<{
        id: string;
        createdAt: Date;
        updatedAt: Date;
        name: string;
        slug: string;
        credits: number;
        lastCreditedAt: Date;
        lastDebitAt: Date | null;
        scanSuspendedAt: Date | null;
        ownerId: string | null;
    } | null>;
    create(payload: CreateOrganizationDto): Promise<{
        id: string;
        createdAt: Date;
        updatedAt: Date;
        name: string;
        slug: string;
        credits: number;
        lastCreditedAt: Date;
        lastDebitAt: Date | null;
        scanSuspendedAt: Date | null;
        ownerId: string | null;
    } & {
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
    update(id: string, payload: UpdateOrganizationDto): Promise<{
        id: string;
        createdAt: Date;
        updatedAt: Date;
        name: string;
        slug: string;
        credits: number;
        lastCreditedAt: Date;
        lastDebitAt: Date | null;
        scanSuspendedAt: Date | null;
        ownerId: string | null;
    }>;
    addCredits(id: string, payload: UpdateOrganizationCreditsDto): Promise<{
        credits: number;
    }>;
}
//# sourceMappingURL=organization.controller.d.ts.map