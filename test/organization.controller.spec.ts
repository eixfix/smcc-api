import { Test, TestingModule } from '@nestjs/testing';
import { Role } from '@prisma/client';

import { CreateOrganizationDto } from '../src/modules/organization/dto/create-organization.dto';
import { UpdateOrganizationDto } from '../src/modules/organization/dto/update-organization.dto';
import { OrganizationController } from '../src/modules/organization/organization.controller';
import { OrganizationService } from '../src/modules/organization/organization.service';

const mockOrganization = {
  id: 'org_1',
  name: 'Zycas',
  slug: 'zycas',
  createdAt: new Date(),
  updatedAt: new Date(),
  ownerId: null
};

describe('OrganizationController', () => {
  let controller: OrganizationController;
  let service: jest.Mocked<OrganizationService>;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [OrganizationController],
      providers: [
        {
          provide: OrganizationService,
          useValue: {
            findAll: jest.fn().mockResolvedValue([mockOrganization]),
            findOne: jest.fn().mockResolvedValue(mockOrganization),
            create: jest.fn().mockResolvedValue(mockOrganization),
            update: jest.fn().mockResolvedValue(mockOrganization)
          }
        }
      ]
    }).compile();

    controller = module.get<OrganizationController>(OrganizationController);
    service = module.get(OrganizationService);
  });

  it('lists organizations', async () => {
    await expect(controller.findAll(mockUser)).resolves.toEqual([mockOrganization]);
    expect(service.findAll).toHaveBeenCalledWith(mockUser);
  });

  it('creates organization', async () => {
    const payload: CreateOrganizationDto = {
      name: 'Acme',
      slug: 'acme',
      owner: {
        name: 'Owner',
        email: 'owner@acme.com',
        password: 'password123'
      }
    };
    await controller.create(payload);
    expect(service.create).toHaveBeenCalledWith(payload);
  });

  it('updates organization', async () => {
    const payload: UpdateOrganizationDto = { name: 'Updated' };
    await controller.update('org_1', payload);
    expect(service.update).toHaveBeenCalledWith('org_1', payload);
  });
});
const mockUser = {
  userId: 'user_1',
  email: 'owner@example.com',
  role: Role.ADMINISTRATOR
};
