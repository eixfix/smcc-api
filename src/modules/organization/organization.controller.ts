import { Body, Controller, Get, Param, Post, Put } from '@nestjs/common';
import { Role } from '@prisma/client';

import { CreateOrganizationDto } from './dto/create-organization.dto';
import { UpdateOrganizationDto } from './dto/update-organization.dto';
import { UpdateOrganizationCreditsDto } from './dto/update-organization-credits.dto';
import { OrganizationService } from './organization.service';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { Roles } from '../../common/decorators/roles.decorator';
import type { AuthenticatedUser } from '../../common/types/auth-user';

@Controller('organizations')
export class OrganizationController {
  constructor(private readonly organizationService: OrganizationService) {}

  @Get()
  findAll(@CurrentUser() user: AuthenticatedUser) {
    return this.organizationService.findAll(user);
  }

  @Get(':id')
  findOne(@Param('id') id: string, @CurrentUser() user: AuthenticatedUser) {
    return this.organizationService.findOne(id, user);
  }

  @Post()
  @Roles(Role.ADMINISTRATOR)
  create(@Body() payload: CreateOrganizationDto) {
    return this.organizationService.create(payload);
  }

  @Put(':id')
  @Roles(Role.ADMINISTRATOR)
  update(@Param('id') id: string, @Body() payload: UpdateOrganizationDto) {
    return this.organizationService.update(id, payload);
  }

  @Post(':id/credits')
  @Roles(Role.ADMINISTRATOR)
  addCredits(
    @Param('id') id: string,
    @Body() payload: UpdateOrganizationCreditsDto
  ) {
    return this.organizationService.addCredits(id, payload.amount);
  }
}
