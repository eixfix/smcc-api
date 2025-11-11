import type { Response } from 'express';
import { CreateTaskDto } from './dto/create-task.dto';
import { UpdateTaskDto } from './dto/update-task.dto';
import { TaskService } from './task.service';
import type { AuthenticatedUser } from '../../common/types/auth-user';
export declare class TaskController {
    private readonly taskService;
    constructor(taskService: TaskService);
    findAll(projectId: string, user: AuthenticatedUser): Promise<{
        id: string;
        createdAt: Date;
        projectId: string;
        label: string;
        targetUrl: string;
        mode: import(".prisma/client").$Enums.TaskMode;
        scheduleAt: Date | null;
        method: string;
        headers: import("@prisma/client/runtime/library").JsonValue | null;
        payload: string | null;
        customVus: number | null;
        durationSeconds: number | null;
        updatedAt: Date;
    }[]>;
    create(projectId: string, payload: CreateTaskDto, user: AuthenticatedUser): Promise<{
        id: string;
        createdAt: Date;
        projectId: string;
        label: string;
        targetUrl: string;
        mode: import(".prisma/client").$Enums.TaskMode;
        scheduleAt: Date | null;
        method: string;
        headers: import("@prisma/client/runtime/library").JsonValue | null;
        payload: string | null;
        customVus: number | null;
        durationSeconds: number | null;
        updatedAt: Date;
    }>;
    update(taskId: string, payload: UpdateTaskDto, user: AuthenticatedUser): Promise<{
        id: string;
        createdAt: Date;
        projectId: string;
        label: string;
        targetUrl: string;
        mode: import(".prisma/client").$Enums.TaskMode;
        scheduleAt: Date | null;
        method: string;
        headers: import("@prisma/client/runtime/library").JsonValue | null;
        payload: string | null;
        customVus: number | null;
        durationSeconds: number | null;
        updatedAt: Date;
    }>;
    run(taskId: string, user: AuthenticatedUser): Promise<{
        id: string;
        status: string;
        startedAt: Date;
        completedAt: Date | null;
        summaryJson: import("@prisma/client/runtime/library").JsonValue;
        taskId: string;
    }>;
    findReports(taskId: string, user: AuthenticatedUser): Promise<{
        id: string;
        status: string;
        startedAt: Date;
        completedAt: Date | null;
        summaryJson: import("@prisma/client/runtime/library").JsonValue;
        taskId: string;
    }[]>;
    exportRecent(user: AuthenticatedUser, res: Response): Promise<void>;
    findRecent(user: AuthenticatedUser): Promise<({
        id: string;
        status: string;
        startedAt: Date;
        completedAt: Date | null;
        summaryJson: import("@prisma/client/runtime/library").JsonValue;
        taskId: string;
    } & {
        task: {
            id: string;
            label: string;
            method?: string;
            targetUrl?: string | null;
            headers?: import("@prisma/client/runtime/library").JsonValue | null;
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
    })[]>;
}
//# sourceMappingURL=task.controller.d.ts.map