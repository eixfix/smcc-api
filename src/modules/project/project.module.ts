import { Module } from '@nestjs/common';

import { ProjectController } from './project.controller';
import { ProjectService } from './project.service';
import { OrganizationModule } from '../organization/organization.module';

@Module({
  imports: [OrganizationModule],
  controllers: [ProjectController],
  providers: [ProjectService]
})
export class ProjectModule {}
