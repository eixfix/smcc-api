import { Module } from '@nestjs/common';

import { PrismaModule } from '../../prisma/prisma.module';
import { UptimeController } from './uptime.controller';
import { UptimeNotifierService } from './uptime-notifier.service';
import { UptimeService } from './uptime.service';

@Module({
  imports: [PrismaModule],
  controllers: [UptimeController],
  providers: [UptimeService, UptimeNotifierService],
  exports: [UptimeService]
})
export class UptimeModule {}
