import { Controller, Get, Post, Req, UseGuards } from '@nestjs/common';
import type { Role } from '@prisma/client';
import type { Request } from 'express';
import { Throttle } from '@nestjs/throttler';

import { Public } from '../../common/decorators/public.decorator';
import { AuthService } from './auth.service';
import { LocalAuthGuard } from './guards/local-auth.guard';

type AuthenticatedRequest = Request & {
  user: {
    userId?: string;
  };
};

type LocalAuthenticatedRequest = Request & {
  user: {
    id: string;
    email: string;
    name: string;
    role: Role;
  };
};

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Public()
  @Throttle({ default: { limit: 5, ttl: 60 } })
  @UseGuards(LocalAuthGuard)
  @Post('login')
  login(@Req() req: LocalAuthenticatedRequest) {
    return this.authService.login(req.user);
  }

  @Get('me')
  getProfile(@Req() req: AuthenticatedRequest) {
    if (!req.user.userId) {
      throw new Error('Authenticated request is missing userId');
    }

    return this.authService.profile(req.user.userId);
  }
}
