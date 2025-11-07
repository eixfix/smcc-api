import { Module } from '@nestjs/common';

import { OrganizationController } from './organization.controller';
import { OrganizationCreditService } from './organization-credit.service';
import { OrganizationService } from './organization.service';

@Module({
  controllers: [OrganizationController],
  providers: [OrganizationService, OrganizationCreditService],
  exports: [OrganizationCreditService, OrganizationService]
})
export class OrganizationModule {}
