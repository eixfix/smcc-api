import { Controller, Get } from '@nestjs/common';

import { CurrentUser } from '../../common/decorators/current-user.decorator';
import type { AuthenticatedUser } from '../../common/types/auth-user';
import { AnalyticsService, type LatencyAnomaly } from './analytics.service';

@Controller('analytics')
export class AnalyticsController {
  constructor(private readonly analyticsService: AnalyticsService) {}

  @Get('anomalies')
  getLatencyAnomalies(@CurrentUser() user: AuthenticatedUser): Promise<LatencyAnomaly[]> {
    return this.analyticsService.findLatencyAnomalies(user);
  }
}
