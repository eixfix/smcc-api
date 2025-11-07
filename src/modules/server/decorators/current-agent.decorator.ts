import { createParamDecorator, ExecutionContext } from '@nestjs/common';

import type { AgentSessionContext } from '../guards/agent-session.guard';

export const CurrentAgent = createParamDecorator(
  (data: unknown, ctx: ExecutionContext): AgentSessionContext | undefined => {
    const request = ctx.switchToHttp().getRequest<{ agent?: AgentSessionContext }>();
    return request.agent;
  }
);
