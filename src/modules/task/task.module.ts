import { Module } from '@nestjs/common';

import { TaskController } from './task.controller';
import { TaskService } from './task.service';
import { TaskRunnerService } from './task-runner.service';
import { OrganizationModule } from '../organization/organization.module';

@Module({
  imports: [OrganizationModule],
  controllers: [TaskController],
  providers: [TaskService, TaskRunnerService]
})
export class TaskModule {}
