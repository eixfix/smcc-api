import { Body, Controller, Get, Param, Patch, Post, Query } from '@nestjs/common';
import { Role } from '@prisma/client';

import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { Roles } from '../../common/decorators/roles.decorator';
import type { AuthenticatedUser } from '../../common/types/auth-user';
import { CreateUptimeTargetDto } from './dto/create-uptime-target.dto';
import { TestWebhookDto } from './dto/test-webhook.dto';
import { UpdateUptimeTargetDto } from './dto/update-uptime-target.dto';
import { UptimeService } from './uptime.service';

@Controller('organizations/:organizationId/uptime')
export class UptimeController {
  constructor(private readonly uptimeService: UptimeService) {}

  @Get('targets')
  listTargets(@Param('organizationId') organizationId: string, @CurrentUser() user: AuthenticatedUser) {
    return this.uptimeService.listTargets(organizationId, user);
  }

  @Post('targets')
  @Roles(Role.ADMINISTRATOR, Role.OWNER)
  createTarget(
    @Param('organizationId') organizationId: string,
    @Body() payload: CreateUptimeTargetDto,
    @CurrentUser() user: AuthenticatedUser
  ) {
    return this.uptimeService.createTarget(organizationId, payload, user);
  }

  @Get('targets/:targetId')
  getTarget(
    @Param('organizationId') organizationId: string,
    @Param('targetId') targetId: string,
    @CurrentUser() user: AuthenticatedUser
  ) {
    return this.uptimeService.getTarget(organizationId, targetId, user);
  }

  @Patch('targets/:targetId')
  @Roles(Role.ADMINISTRATOR, Role.OWNER)
  updateTarget(
    @Param('organizationId') organizationId: string,
    @Param('targetId') targetId: string,
    @Body() payload: UpdateUptimeTargetDto,
    @CurrentUser() user: AuthenticatedUser
  ) {
    return this.uptimeService.updateTarget(organizationId, targetId, payload, user);
  }

  @Get('targets/:targetId/checks')
  listChecks(
    @Param('organizationId') organizationId: string,
    @Param('targetId') targetId: string,
    @Query('limit') limit: string | undefined,
    @CurrentUser() user: AuthenticatedUser
  ) {
    const parsedLimit = limit ? Number.parseInt(limit, 10) : undefined;
    const safeLimit = parsedLimit && !Number.isNaN(parsedLimit) ? parsedLimit : undefined;
    return this.uptimeService.listChecks(organizationId, targetId, user, safeLimit);
  }

  @Post('targets/:targetId/run')
  runCheck(
    @Param('organizationId') organizationId: string,
    @Param('targetId') targetId: string,
    @CurrentUser() user: AuthenticatedUser
  ) {
    return this.uptimeService.runCheckNow(organizationId, targetId, user);
  }

  @Post('targets/:targetId/test-webhook')
  @Roles(Role.ADMINISTRATOR, Role.OWNER)
  testWebhook(
    @Param('organizationId') organizationId: string,
    @Param('targetId') targetId: string,
    @Body() payload: TestWebhookDto,
    @CurrentUser() user: AuthenticatedUser
  ) {
    return this.uptimeService.testWebhook(organizationId, targetId, payload, user);
  }
}
