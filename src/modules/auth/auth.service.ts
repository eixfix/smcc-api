import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import type { Role, User } from '@prisma/client';
import * as bcrypt from 'bcryptjs';

import { UserService } from '../user/user.service';

type SanitizedUser = Pick<User, 'id' | 'email' | 'name' | 'role'> & { role: Role };

@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UserService,
    private readonly jwtService: JwtService
  ) {}

  async validateUser(email: string, password: string): Promise<SanitizedUser> {
    const user = await this.usersService.findByEmail(email);

    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const isValid = await bcrypt.compare(password, user.passwordHash);

    if (!isValid) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const { passwordHash: _passwordHash, ...rest } = user;
    void _passwordHash;

    return rest;
  }

  async login(user: SanitizedUser): Promise<{ accessToken: string; user: SanitizedUser }> {
    const payload = {
      sub: user.id,
      email: user.email,
      role: user.role
    };

    const accessToken = await this.jwtService.signAsync(payload);

    return { accessToken, user };
  }

  async profile(userId: string): Promise<SanitizedUser> {
    const user = await this.usersService.findById(userId);

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    const { passwordHash: _passwordHash, ...rest } = user;
    void _passwordHash;
    return rest;
  }
}
