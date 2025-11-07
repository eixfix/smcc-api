import { TaskMode } from '@prisma/client';
export declare class HttpHeaderDto {
    key: string;
    value: string;
}
export declare class CreateTaskDto {
    label: string;
    targetUrl: string;
    mode: TaskMode;
    scheduleAt?: string;
    method?: string;
    headers?: HttpHeaderDto[];
    payload?: string;
    customVus?: number;
    durationSeconds?: number;
}
//# sourceMappingURL=create-task.dto.d.ts.map