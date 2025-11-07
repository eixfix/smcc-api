import type { Task, TaskReport } from '@prisma/client';
import { Prisma } from '@prisma/client';
import type { Response } from 'express';
import { PrismaService } from '../../prisma/prisma.service';
import type { AuthenticatedUser } from '../../common/types/auth-user';
import { TaskRunnerService } from './task-runner.service';
import { CreateTaskDto } from './dto/create-task.dto';
import { UpdateTaskDto } from './dto/update-task.dto';
import { OrganizationCreditService } from '../organization/organization-credit.service';
export declare class TaskService {
    private readonly prisma;
    private readonly taskRunner;
    private readonly creditService;
    private readonly logger;
    constructor(prisma: PrismaService, taskRunner: TaskRunnerService, creditService: OrganizationCreditService);
    findAllByProject(projectId: string, user: AuthenticatedUser): Promise<Task[]>;
    create(projectId: string, payload: CreateTaskDto, user: AuthenticatedUser): Promise<Task>;
    update(id: string, payload: UpdateTaskDto, user: AuthenticatedUser): Promise<Task>;
    run(taskId: string, user: AuthenticatedUser): Promise<TaskReport>;
    private normalizeMethod;
    private normalizeHeaders;
    private headersFromJson;
    private normalizePayload;
    private normalizePositiveInteger;
    findReports(taskId: string, user: AuthenticatedUser): Promise<TaskReport[]>;
    findRecentReports(user: AuthenticatedUser): Promise<Array<TaskReport & {
        task: {
            id: string;
            label: string;
            method?: string;
            targetUrl?: string | null;
            headers?: Prisma.JsonValue | null;
            payload?: string | null;
            project: {
                id: string;
                name: string;
                organization: {
                    id: string;
                    name: string;
                    slug: string;
                };
            };
        };
    }>>;
    exportRecentReportsPdf(user: AuthenticatedUser, res: Response): Promise<void>;
    private buildAggregateSummary;
    private parseSummary;
    private normalizeDate;
    private verifyProjectAccess;
}
//# sourceMappingURL=task.service.d.ts.map