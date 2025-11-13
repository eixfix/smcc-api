import { Test, TestingModule } from '@nestjs/testing';
import { Role } from '@prisma/client';

import type { AuthenticatedUser } from '../src/common/types/auth-user';
import { ServerController } from '../src/modules/server/server.controller';
import { ServerService } from '../src/modules/server/server.service';

const mockUser: AuthenticatedUser = {
  userId: 'user_1',
  email: 'owner@example.com',
  role: Role.OWNER
};

describe('ServerController', () => {
  let controller: ServerController;
  let service: jest.Mocked<ServerService>;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [ServerController],
      providers: [
        {
          provide: ServerService,
          useValue: {
            findAll: jest.fn().mockResolvedValue([]),
            findOne: jest.fn().mockResolvedValue(null),
            create: jest.fn().mockResolvedValue({ id: 'srv_1' }),
            update: jest.fn().mockResolvedValue({ id: 'srv_1' }),
            setSuspension: jest.fn().mockResolvedValue({ id: 'srv_1', isSuspended: true }),
            listTelemetry: jest.fn().mockResolvedValue([])
          }
        }
      ]
    }).compile();

    controller = module.get(ServerController);
    service = module.get(ServerService);
  });

  it('delegates list call to service with filters', async () => {
    await controller.findAll(mockUser, 'org_123');
    expect(service.findAll).toHaveBeenCalledWith(mockUser, 'org_123');
  });

  it('retrieves single server', async () => {
    await controller.findOne('srv_1', mockUser);
    expect(service.findOne).toHaveBeenCalledWith('srv_1', mockUser);
  });

  it('creates server', async () => {
    await controller.create(
      {
        organizationId: 'org_1',
        name: 'Primary',
        allowedIp: '10.0.0.10'
      },
      mockUser
    );

    expect(service.create).toHaveBeenCalledWith(
      {
        organizationId: 'org_1',
        name: 'Primary',
        allowedIp: '10.0.0.10'
      },
      mockUser
    );
  });

  it('updates server', async () => {
    await controller.update('srv_1', { name: 'Updated' }, mockUser);
    expect(service.update).toHaveBeenCalledWith('srv_1', { name: 'Updated' }, mockUser);
  });

  it('suspends server', async () => {
    await controller.suspend('srv_1', mockUser);
    expect(service.setSuspension).toHaveBeenCalledWith('srv_1', true, mockUser);
  });

  it('unsuspends server', async () => {
    await controller.unsuspend('srv_1', mockUser);
    expect(service.setSuspension).toHaveBeenCalledWith('srv_1', false, mockUser);
  });

  it('lists telemetry history with parsed limit', async () => {
    await controller.listTelemetry('srv_1', mockUser, '10');
    expect(service.listTelemetry).toHaveBeenCalledWith('srv_1', mockUser, 10);
  });

  it('falls back to default telemetry limit on invalid input', async () => {
    await controller.listTelemetry('srv_1', mockUser, 'not-a-number');
    expect(service.listTelemetry).toHaveBeenCalledWith('srv_1', mockUser, undefined);
  });
});
