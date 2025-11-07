import type { Project } from '@prisma/client';
import { PrismaService } from '../../prisma/prisma.service';
import type { AuthenticatedUser } from '../../common/types/auth-user';
import { CreateProjectDto } from './dto/create-project.dto';
import { UpdateProjectDto } from './dto/update-project.dto';
import { OrganizationCreditService } from '../organization/organization-credit.service';
export declare class ProjectService {
    private readonly prisma;
    private readonly creditService;
    constructor(prisma: PrismaService, creditService: OrganizationCreditService);
    findAllByOrganization(organizationId: string, user: AuthenticatedUser): Promise<Project[]>;
    create(organizationId: string, payload: CreateProjectDto, user: AuthenticatedUser): Promise<Project>;
    update(id: string, payload: UpdateProjectDto, user: AuthenticatedUser): Promise<Project>;
    private verifyOrganizationAccess;
}
//# sourceMappingURL=project.service.d.ts.map