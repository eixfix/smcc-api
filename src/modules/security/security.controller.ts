import { Body, Controller, Post } from '@nestjs/common';
import { Throttle } from '@nestjs/throttler';

import { CurrentUser } from '../../common/decorators/current-user.decorator';
import type { AuthenticatedUser } from '../../common/types/auth-user';
import { CheckEndpointDto } from './dto/check-endpoint.dto';
import { SecurityService } from './security.service';

@Controller('security')
export class SecurityController {
  constructor(private readonly securityService: SecurityService) {}

  @Throttle({ default: { limit: 3, ttl: 60 } })
  @Post('check')
  checkEndpoint(
    @Body() payload: CheckEndpointDto,
    @CurrentUser() user: AuthenticatedUser
  ) {
    return this.securityService.checkEndpoint(payload.organizationId, payload.url, user);
  }
}
