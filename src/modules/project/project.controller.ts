import { Body, Controller, Get, Param, Post, Put } from '@nestjs/common';

import { CreateProjectDto } from './dto/create-project.dto';
import { UpdateProjectDto } from './dto/update-project.dto';
import { ProjectService } from './project.service';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import type { AuthenticatedUser } from '../../common/types/auth-user';

@Controller('organizations/:organizationId/projects')
export class ProjectController {
  constructor(private readonly projectService: ProjectService) {}

  @Get()
  findAll(
    @Param('organizationId') organizationId: string,
    @CurrentUser() user: AuthenticatedUser
  ) {
    return this.projectService.findAllByOrganization(organizationId, user);
  }

  @Post()
  create(
    @Param('organizationId') organizationId: string,
    @Body() payload: CreateProjectDto,
    @CurrentUser() user: AuthenticatedUser
  ) {
    return this.projectService.create(organizationId, payload, user);
  }

  @Put(':projectId')
  update(
    @Param('projectId') projectId: string,
    @Body() payload: UpdateProjectDto,
    @CurrentUser() user: AuthenticatedUser
  ) {
    return this.projectService.update(projectId, payload, user);
  }
}
