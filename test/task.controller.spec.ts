import { Test, TestingModule } from '@nestjs/testing';
import { Role, TaskMode } from '@prisma/client';

import { CreateTaskDto } from '../src/modules/task/dto/create-task.dto';
import { UpdateTaskDto } from '../src/modules/task/dto/update-task.dto';
import { TaskController } from '../src/modules/task/task.controller';
import { TaskService } from '../src/modules/task/task.service';

const mockTask = {
  id: 'task_1',
  projectId: 'proj_1',
  label: 'Smoke Run',
  targetUrl: 'https://example.com',
  mode: TaskMode.SMOKE,
  scheduleAt: null,
  createdAt: new Date(),
  updatedAt: new Date()
};

describe('TaskController', () => {
  let controller: TaskController;
  let service: jest.Mocked<TaskService>;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [TaskController],
      providers: [
        {
          provide: TaskService,
          useValue: {
            findAllByProject: jest.fn().mockResolvedValue([mockTask]),
            create: jest.fn().mockResolvedValue(mockTask),
            update: jest.fn().mockResolvedValue(mockTask)
          }
        }
      ]
    }).compile();

    controller = module.get(TaskController);
    service = module.get(TaskService);
  });

  it('lists tasks for project', async () => {
    await expect(controller.findAll('proj_1', mockUser)).resolves.toEqual([mockTask]);
    expect(service.findAllByProject).toHaveBeenCalledWith('proj_1', mockUser);
  });

  it('creates task', async () => {
    const payload: CreateTaskDto = {
      label: 'Smoke',
      targetUrl: 'https://example.com',
      mode: TaskMode.SMOKE
    };

    await controller.create('proj_1', payload, mockUser);
    expect(service.create).toHaveBeenCalledWith('proj_1', payload, mockUser);
  });

  it('updates task', async () => {
    const payload: UpdateTaskDto = { label: 'Updated' };
    await controller.update('task_1', payload, mockUser);
    expect(service.update).toHaveBeenCalledWith('task_1', payload, mockUser);
  });
});
const mockUser = {
  userId: 'user_1',
  email: 'owner@example.com',
  role: Role.ADMINISTRATOR
};
