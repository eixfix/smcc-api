import type { AuthenticatedUser } from '../../common/types/auth-user';
import { AnalyticsService, type LatencyAnomaly } from './analytics.service';
export declare class AnalyticsController {
    private readonly analyticsService;
    constructor(analyticsService: AnalyticsService);
    getLatencyAnomalies(user: AuthenticatedUser): Promise<LatencyAnomaly[]>;
}
//# sourceMappingURL=analytics.controller.d.ts.map