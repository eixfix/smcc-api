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
    private readonly npmPath;
    private readonly k6Path;
    private readonly scriptByMode;
    constructor();
    enqueue(request: RunRequest): Promise<TaskRunSummary>;
    private processQueue;
    private buildBundles;
    private execute;
    private execCommand;
    private normalizeExecutable;
    private toSummary;
    private toMetricsRecord;
    private toMetricSnapshot;
    private toFiniteNumber;
}
export {};
//# sourceMappingURL=task-runner.service.d.ts.map