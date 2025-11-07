import { Body, Controller, Get, Param, Post, Put, Res } from '@nestjs/common';
import type { Response } from 'express';

import { CreateTaskDto } from './dto/create-task.dto';
import { UpdateTaskDto } from './dto/update-task.dto';
import { TaskService } from './task.service';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import type { AuthenticatedUser } from '../../common/types/auth-user';

@Controller('projects/:projectId/tasks')
export class TaskController {
  constructor(private readonly taskService: TaskService) {}

  @Get()
  findAll(
    @Param('projectId') projectId: string,
    @CurrentUser() user: AuthenticatedUser
  ) {
    return this.taskService.findAllByProject(projectId, user);
  }

  @Post()
  create(
    @Param('projectId') projectId: string,
    @Body() payload: CreateTaskDto,
    @CurrentUser() user: AuthenticatedUser
  ) {
    return this.taskService.create(projectId, payload, user);
  }

  @Put(':taskId')
  update(
    @Param('taskId') taskId: string,
    @Body() payload: UpdateTaskDto,
    @CurrentUser() user: AuthenticatedUser
  ) {
    return this.taskService.update(taskId, payload, user);
  }

  @Post(':taskId/run')
  run(@Param('taskId') taskId: string, @CurrentUser() user: AuthenticatedUser) {
    return this.taskService.run(taskId, user);
  }

  @Get(':taskId/reports')
  findReports(@Param('taskId') taskId: string, @CurrentUser() user: AuthenticatedUser) {
    return this.taskService.findReports(taskId, user);
  }

  @Get('reports/recent/export')
  async exportRecent(
    @CurrentUser() user: AuthenticatedUser,
    @Res() res: Response
  ) {
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader(
      'Content-Disposition',
      `attachment; filename="load-test-report-${new Date().toISOString().slice(0, 10)}.pdf"`
    );
    await this.taskService.exportRecentReportsPdf(user, res);
  }

  @Get('reports/recent')
  findRecent(@CurrentUser() user: AuthenticatedUser) {
    return this.taskService.findRecentReports(user);
  }
}
