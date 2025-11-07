type RunRequest = {
    taskId: string;
    targetUrl: string;
    mode: string;
    method: string;
    headers?: Record<string, string>;
    payload?: string;
    customVus?: number;
    durationSeconds?: number;
};
export type TaskRunSummary = {
    status: 'completed' | 'failed';
    startedAt: Date;
    completedAt: Date;
    summary: Record<string, unknown> | null;
};
export declare class TaskRunnerService {
    private readonly logger;
    private readonly queue;
    private running;
    private bundleReady;
    private readonly loadTestsRoot;
    private readonly scriptByMode;
    enqueue(request: RunRequest): Promise<TaskRunSummary>;
    private processQueue;
    private buildBundles;
    private execute;
    private execCommand;
    private toSummary;
}
export {};
//# sourceMappingURL=task-runner.service.d.ts.map