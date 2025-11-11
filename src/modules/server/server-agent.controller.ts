import {
  Body,
  Controller,
  ForbiddenException,
  Get,
  Param,
  Post,
  Query,
  Req,
  UseGuards,
  UseInterceptors
} from '@nestjs/common';
import { Role } from '@prisma/client';
import type { Request } from 'express';

import { Public } from '../../common/decorators/public.decorator';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { Roles } from '../../common/decorators/roles.decorator';
import type { AuthenticatedUser } from '../../common/types/auth-user';
import { CurrentAgent } from './decorators/current-agent.decorator';
import { AgentAuthDto } from './dto/agent-auth.dto';
import { CreateServerAgentDto } from './dto/create-server-agent.dto';
import type { AgentSessionContext } from './guards/agent-session.guard';
import { AgentSessionGuard } from './guards/agent-session.guard';
import { AgentEnvelopeInterceptor } from './interceptors/agent-envelope.interceptor';
import { ServerAgentService } from './server-agent.service';
import { extractClientIp } from '../../common/utils/ip.utils';

interface AgentCapabilityRequest extends Request {
  agentCapabilities?: string[];
}

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

  @Public()
  @Get('agent/config')
  @UseGuards(AgentSessionGuard)
  @UseInterceptors(AgentEnvelopeInterceptor)
  fetchConfig(
    @Req() request: AgentCapabilityRequest,
    @CurrentAgent() agent: AgentSessionContext | undefined
  ) {
    this.assertCapability(request, 'config_v1');
    if (!agent) {
      throw new ForbiddenException('Agent session missing from request context.');
    }
    return this.serverAgentService.getRemoteConfig(agent);
  }

  @Public()
  @Get('agent/update')
  @UseGuards(AgentSessionGuard)
  @UseInterceptors(AgentEnvelopeInterceptor)
  fetchUpdateManifest(
    @Req() request: AgentCapabilityRequest,
    @CurrentAgent() agent: AgentSessionContext | undefined,
    @Query('currentVersion') currentVersion?: string
  ) {
    this.assertCapability(request, 'update_v1');
    if (!agent) {
      throw new ForbiddenException('Agent session missing from request context.');
    }
    return this.serverAgentService.getUpdateManifest(agent, currentVersion);
  }

  private assertCapability(request: AgentCapabilityRequest, capability: string) {
    const capabilities = request.agentCapabilities ?? [];
    if (!capabilities.includes(capability)) {
      throw new ForbiddenException(`Agent is missing required capability: ${capability}`);
    }
  }
}
