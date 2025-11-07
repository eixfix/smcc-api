import { Test, TestingModule } from '@nestjs/testing';
import { Role } from '@prisma/client';

import { CreateProjectDto } from '../src/modules/project/dto/create-project.dto';
import { UpdateProjectDto } from '../src/modules/project/dto/update-project.dto';
import { ProjectController } from '../src/modules/project/project.controller';
import { ProjectService } from '../src/modules/project/project.service';

const mockProject = {
  id: 'proj_1',
  organizationId: 'org_1',
  name: 'API Service',
  description: null,
  createdAt: new Date(),
  updatedAt: new Date()
};

describe('ProjectController', () => {
  let controller: ProjectController;
  let service: jest.Mocked<ProjectService>;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [ProjectController],
      providers: [
        {
          provide: ProjectService,
          useValue: {
            findAllByOrganization: jest.fn().mockResolvedValue([mockProject]),
            create: jest.fn().mockResolvedValue(mockProject),
            update: jest.fn().mockResolvedValue(mockProject)
          }
        }
      ]
    }).compile();

    controller = module.get(ProjectController);
    service = module.get(ProjectService);
  });

  it('retrieves projects for organization', async () => {
    await expect(controller.findAll('org_1', mockUser)).resolves.toEqual([mockProject]);
    expect(service.findAllByOrganization).toHaveBeenCalledWith('org_1', mockUser);
  });

  it('creates project', async () => {
    const payload: CreateProjectDto = { name: 'UI', description: 'Dashboard' };
    await controller.create('org_1', payload, mockUser);
    expect(service.create).toHaveBeenCalledWith('org_1', payload, mockUser);
  });

  it('updates project', async () => {
    const payload: UpdateProjectDto = { name: 'Updated' };
    await controller.update('proj_1', payload, mockUser);
    expect(service.update).toHaveBeenCalledWith('proj_1', payload, mockUser);
  });
});
const mockUser = {
  userId: 'user_1',
  email: 'owner@example.com',
  role: Role.ADMINISTRATOR
};
