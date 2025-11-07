import type { AuthenticatedUser } from '../../common/types/auth-user';
import { PrismaService } from '../../prisma/prisma.service';
export type LatencyAnomaly = {
    reportId: string;
    taskId: string;
    taskLabel: string;
    projectName: string;
    organizationName: string;
    startedAt: string;
    metric: 'p95Ms';
    value: number;
    baselineMean: number;
    baselineStdDev: number;
    zScore: number;
    successRate: number | null;
};
export declare class AnalyticsService {
    private readonly prisma;
    private static readonly MIN_SAMPLE_SIZE;
    private static readonly Z_THRESHOLD;
    constructor(prisma: PrismaService);
    findLatencyAnomalies(user: AuthenticatedUser): Promise<LatencyAnomaly[]>;
    private buildScope;
    private toLatencySample;
    private extractMetrics;
    private toNumber;
    private mean;
    private stdDev;
}
//# sourceMappingURL=analytics.service.d.ts.map