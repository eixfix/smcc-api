import { Test, TestingModule } from '@nestjs/testing';
import { Role } from '@prisma/client';

import type { AuthenticatedUser } from '../src/common/types/auth-user';
import { AgentAuthDto } from '../src/modules/server/dto/agent-auth.dto';
import { CreateServerAgentDto } from '../src/modules/server/dto/create-server-agent.dto';
import { ServerAgentController } from '../src/modules/server/server-agent.controller';
import { ServerAgentService } from '../src/modules/server/server-agent.service';

const mockUser: AuthenticatedUser = {
  userId: 'user_1',
  email: 'owner@example.com',
  role: Role.OWNER
};

describe('ServerAgentController', () => {
  let controller: ServerAgentController;
  let service: jest.Mocked<ServerAgentService>;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [ServerAgentController],
      providers: [
        {
          provide: ServerAgentService,
          useValue: {
            mintAgentToken: jest.fn(),
            revokeAgent: jest.fn(),
            authenticateAgent: jest.fn()
          }
        }
      ]
    }).compile();

    controller = module.get(ServerAgentController);
    service = module.get(ServerAgentService);
  });

  it('creates agent token', async () => {
    const payload: CreateServerAgentDto = {};
    await controller.createAgent('srv_1', payload, mockUser);
    expect(service.mintAgentToken).toHaveBeenCalledWith('srv_1', payload, mockUser);
  });

  it('revokes agent token', async () => {
    await controller.revokeAgent('agent_1', mockUser);
    expect(service.revokeAgent).toHaveBeenCalledWith('agent_1', mockUser);
  });

  it('authenticates agent', async () => {
    const payload: AgentAuthDto = {
      serverId: 'srv_1',
      accessKey: 'agt_token',
      secret: 'plaintext'
    };

    await controller.authenticate(payload);
    expect(service.authenticateAgent).toHaveBeenCalledWith(payload);
  });
});
