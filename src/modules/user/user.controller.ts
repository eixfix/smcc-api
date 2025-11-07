import { Body, Controller, Patch } from '@nestjs/common';

import { CurrentUser } from '../../common/decorators/current-user.decorator';
import type { AuthenticatedUser } from '../../common/types/auth-user';
import { ChangePasswordDto } from './dto/change-password.dto';
import { UserService } from './user.service';

@Controller('users')
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Patch('me/password')
  changePassword(
    @Body() payload: ChangePasswordDto,
    @CurrentUser() user: AuthenticatedUser
  ) {
    return this.userService.changePassword(user.userId, payload.oldPassword, payload.newPassword);
  }
}
