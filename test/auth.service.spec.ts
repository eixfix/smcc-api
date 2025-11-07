import { Test } from '@nestjs/testing';
import { UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';

import { AuthService } from '../src/modules/auth/auth.service';
import { UserService } from '../src/modules/user/user.service';

const mockUser = {
  id: 'user_1',
  email: 'administrator@mail.com',
  name: 'Administrator',
  passwordHash: '$2b$10$wE8rIF3O13nPqxGN7oG/Xu36q36iJ7D5UtgZ0l7BrUjJiojsLGP8K',
  role: 'ADMINISTRATOR'
};

jest.mock('bcryptjs', () => ({
  compare: jest.fn(async (provided, hashed) => provided === 'open1234' && Boolean(hashed))
}));

describe('AuthService', () => {
  let authService: AuthService;
  let usersService: jest.Mocked<UserService>;
  const signAsync = jest.fn().mockResolvedValue('signed-token');

  beforeEach(async () => {
    const moduleRef = await Test.createTestingModule({
      providers: [
        AuthService,
        {
          provide: UserService,
          useValue: {
            findByEmail: jest.fn(),
            findById: jest.fn()
          }
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
    usersService = moduleRef.get(UserService) as jest.Mocked<UserService>;
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('validates and logs in a user', async () => {
    usersService.findByEmail.mockResolvedValue(mockUser as any);

    const validated = await authService.validateUser('administrator@mail.com', 'open1234');
    expect(validated.email).toBe(mockUser.email);

    const result = await authService.login(validated as any);
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
