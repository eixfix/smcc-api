import { Body, Controller, Param, Post, Req } from '@nestjs/common';
import { Role } from '@prisma/client';
import type { Request } from 'express';

import { Public } from '../../common/decorators/public.decorator';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { Roles } from '../../common/decorators/roles.decorator';
import type { AuthenticatedUser } from '../../common/types/auth-user';
import { AgentAuthDto } from './dto/agent-auth.dto';
import { CreateServerAgentDto } from './dto/create-server-agent.dto';
import { ServerAgentService } from './server-agent.service';
import { extractClientIp } from '../../common/utils/ip.utils';

@Controller()
export class ServerAgentController {
  constructor(private readonly serverAgentService: ServerAgentService) {}

  @Post('servers/:serverId/agents')
  @Roles(Role.ADMINISTRATOR, Role.OWNER)
  createAgent(
    @Param('serverId') serverId: string,
    @Body() payload: CreateServerAgentDto,
    @CurrentUser() user: AuthenticatedUser
  ) {
    return this.serverAgentService.mintAgentToken(serverId, payload, user);
  }

  @Post('servers/:serverId/agents/:agentId/revoke')
  @Roles(Role.ADMINISTRATOR, Role.OWNER)
  revokeAgent(
    @Param('agentId') agentId: string,
    @CurrentUser() user: AuthenticatedUser
  ) {
    return this.serverAgentService.revokeAgent(agentId, user);
  }

  @Public()
  @Post('agent/auth')
  authenticate(@Body() payload: AgentAuthDto, @Req() request: Request) {
    const clientIp = extractClientIp(request);
    return this.serverAgentService.authenticateAgent(payload, clientIp);
  }
}
