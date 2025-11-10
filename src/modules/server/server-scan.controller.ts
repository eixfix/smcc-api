import { Body, Controller, Get, Param, Post, UseGuards, UseInterceptors } from '@nestjs/common';
import { Role } from '@prisma/client';

import { Public } from '../../common/decorators/public.decorator';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { Roles } from '../../common/decorators/roles.decorator';
import type { AuthenticatedUser } from '../../common/types/auth-user';
import { CurrentAgent } from './decorators/current-agent.decorator';
import { QueueServerScanDto } from './dto/queue-server-scan.dto';
import { ReportServerScanDto } from './dto/report-server-scan.dto';
import { TelemetryPayloadDto } from './dto/telemetry-payload.dto';
import type { AgentSessionContext } from './guards/agent-session.guard';
import { AgentSessionGuard } from './guards/agent-session.guard';
import { ServerScanService } from './server-scan.service';
import { AgentEnvelopeInterceptor } from './interceptors/agent-envelope.interceptor';

@Controller()
export class ServerScanController {
  constructor(private readonly serverScanService: ServerScanService) {}

  @Post('servers/:serverId/scans')
  @Roles(Role.ADMINISTRATOR, Role.OWNER)
  queueScan(
    @Param('serverId') serverId: string,
    @Body() payload: QueueServerScanDto,
    @CurrentUser() user: AuthenticatedUser
  ) {
    return this.serverScanService.queueScan(serverId, payload, user);
  }

  @Get('servers/:serverId/scans')
  @Roles(Role.ADMINISTRATOR, Role.OWNER)
  listScans(
    @Param('serverId') serverId: string,
    @CurrentUser() user: AuthenticatedUser
  ) {
    return this.serverScanService.listScans(serverId, user);
  }

  @Public()
  @UseGuards(AgentSessionGuard)
  @UseInterceptors(AgentEnvelopeInterceptor)
  @Post('agent/scans/next')
  fetchNext(@CurrentAgent() agent: AgentSessionContext) {
    return this.serverScanService.getNextQueuedScan(agent);
  }

  @Public()
  @UseGuards(AgentSessionGuard)
  @UseInterceptors(AgentEnvelopeInterceptor)
  @Post('agent/scans/:scanId/report')
  submitReport(
    @Param('scanId') scanId: string,
    @Body() payload: ReportServerScanDto,
    @CurrentAgent() agent: AgentSessionContext
  ) {
    return this.serverScanService.submitScanReport(agent, scanId, payload);
  }

  @Public()
  @UseGuards(AgentSessionGuard)
  @UseInterceptors(AgentEnvelopeInterceptor)
  @Post('agent/telemetry')
  ingestTelemetry(
    @Body() payload: TelemetryPayloadDto,
    @CurrentAgent() agent: AgentSessionContext
  ) {
    return this.serverScanService.ingestTelemetry(agent, payload);
  }
}
