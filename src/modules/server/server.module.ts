import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';

import { OrganizationModule } from '../organization/organization.module';
import { AgentSessionGuard } from './guards/agent-session.guard';
import { ServerAgentController } from './server-agent.controller';
import { ServerAgentService } from './server-agent.service';
import { ServerController } from './server.controller';
import { ServerScanController } from './server-scan.controller';
import { ServerScanService } from './server-scan.service';
import { ServerService } from './server.service';
import { ServerAgentInstallController } from './server-agent-install.controller';

@Module({
  imports: [
    ConfigModule,
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        secret: configService.get<string>('JWT_SECRET'),
        signOptions: {
          expiresIn: '15m'
        }
      })
    }),
    OrganizationModule
  ],
  controllers: [
    ServerController,
    ServerAgentController,
    ServerScanController,
    ServerAgentInstallController
  ],
  providers: [ServerService, ServerAgentService, ServerScanService, AgentSessionGuard]
})
export class ServerModule {}
