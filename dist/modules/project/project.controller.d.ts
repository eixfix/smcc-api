import { CreateProjectDto } from './dto/create-project.dto';
import { UpdateProjectDto } from './dto/update-project.dto';
import { ProjectService } from './project.service';
import type { AuthenticatedUser } from '../../common/types/auth-user';
export declare class ProjectController {
    private readonly projectService;
    constructor(projectService: ProjectService);
    findAll(organizationId: string, user: AuthenticatedUser): Promise<{
        id: string;
        createdAt: Date;
        updatedAt: Date;
        name: string;
        description: string | null;
        organizationId: string;
    }[]>;
    create(organizationId: string, payload: CreateProjectDto, user: AuthenticatedUser): Promise<{
        id: string;
        createdAt: Date;
        updatedAt: Date;
        name: string;
        description: string | null;
        organizationId: string;
    }>;
    update(projectId: string, payload: UpdateProjectDto, user: AuthenticatedUser): Promise<{
        id: string;
        createdAt: Date;
        updatedAt: Date;
        name: string;
        description: string | null;
        organizationId: string;
    }>;
}
//# sourceMappingURL=project.controller.d.ts.map