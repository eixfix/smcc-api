import { Test } from '@nestjs/testing';
import { UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import type { User } from '@prisma/client';
import { Role } from '@prisma/client';

import { AuthService } from '../src/modules/auth/auth.service';
import { UserService } from '../src/modules/user/user.service';

const mockUser: User = {
  id: 'user_1',
  email: 'administrator@mail.com',
  name: 'Administrator',
  passwordHash: '$2b$10$wE8rIF3O13nPqxGN7oG/Xu36q36iJ7D5UtgZ0l7BrUjJiojsLGP8K',
  role: Role.ADMINISTRATOR,
  createdAt: new Date('2024-01-01T00:00:00.000Z'),
  updatedAt: new Date('2024-01-01T00:00:00.000Z')
};

jest.mock('bcryptjs', () => ({
  compare: jest.fn((provided: string, hashed: string) =>
    Promise.resolve(provided === 'open1234' && Boolean(hashed))
  )
}));

const createUserServiceMock = () => ({
  findByEmail: jest.fn(),
  findById: jest.fn()
});

describe('AuthService', () => {
  let authService: AuthService;
  let usersService: ReturnType<typeof createUserServiceMock>;
  const signAsync = jest.fn().mockResolvedValue('signed-token');

  beforeEach(async () => {
    const userServiceMock = createUserServiceMock();

    const moduleRef = await Test.createTestingModule({
      providers: [
        AuthService,
        {
          provide: UserService,
          useValue: userServiceMock
        },
        {
          provide: JwtService,
          useValue: {
            signAsync
          }
        }
      ]
    }).compile();

    authService = moduleRef.get(AuthService);
    usersService = userServiceMock;
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('validates and logs in a user', async () => {
    usersService.findByEmail.mockResolvedValue(mockUser);

    const validated = await authService.validateUser('administrator@mail.com', 'open1234');
    expect(validated.email).toBe(mockUser.email);

    const result = await authService.login(validated);
    expect(signAsync).toHaveBeenCalled();
    expect(result.accessToken).toBe('signed-token');
  });

  it('throws on invalid credentials', async () => {
    usersService.findByEmail.mockResolvedValue(null);

    await expect(authService.validateUser('missing@mail.com', 'open1234')).rejects.toBeInstanceOf(
      UnauthorizedException
    );
  });
});
