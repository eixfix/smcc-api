import { Body, Controller, Get, Param, Patch, Post, Query } from '@nestjs/common';
import { Role } from '@prisma/client';

import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { Roles } from '../../common/decorators/roles.decorator';
import type { AuthenticatedUser } from '../../common/types/auth-user';
import { CreateServerDto } from './dto/create-server.dto';
import { UpdateServerDto } from './dto/update-server.dto';
import { ServerService } from './server.service';

@Controller('servers')
export class ServerController {
  constructor(private readonly serverService: ServerService) {}

  @Get()
  findAll(
    @CurrentUser() user: AuthenticatedUser,
    @Query('organizationId') organizationId?: string
  ) {
    return this.serverService.findAll(user, organizationId);
  }

  @Get(':id')
  findOne(@Param('id') id: string, @CurrentUser() user: AuthenticatedUser) {
    return this.serverService.findOne(id, user);
  }

  @Post()
  @Roles(Role.ADMINISTRATOR, Role.OWNER)
  create(@Body() payload: CreateServerDto, @CurrentUser() user: AuthenticatedUser) {
    return this.serverService.create(payload, user);
  }

  @Patch(':id')
  @Roles(Role.ADMINISTRATOR, Role.OWNER)
  update(
    @Param('id') id: string,
    @Body() payload: UpdateServerDto,
    @CurrentUser() user: AuthenticatedUser
  ) {
    return this.serverService.update(id, payload, user);
  }

  @Post(':id/suspend')
  @Roles(Role.ADMINISTRATOR, Role.OWNER)
  suspend(@Param('id') id: string, @CurrentUser() user: AuthenticatedUser) {
    return this.serverService.setSuspension(id, true, user);
  }

  @Post(':id/unsuspend')
  @Roles(Role.ADMINISTRATOR, Role.OWNER)
  unsuspend(@Param('id') id: string, @CurrentUser() user: AuthenticatedUser) {
    return this.serverService.setSuspension(id, false, user);
  }

  @Get(':id/telemetry')
  listTelemetry(
    @Param('id') id: string,
    @CurrentUser() user: AuthenticatedUser,
    @Query('limit') limit?: string
  ) {
    const parsedLimit = limit ? Number.parseInt(limit, 10) : undefined;
    const sanitizedLimit =
      parsedLimit !== undefined && !Number.isNaN(parsedLimit) ? parsedLimit : undefined;

    return this.serverService.listTelemetry(id, user, sanitizedLimit);
  }
}
