import type { AuthenticatedUser } from '../../common/types/auth-user';
import { ChangePasswordDto } from './dto/change-password.dto';
import { UserService } from './user.service';
export declare class UserController {
    private readonly userService;
    constructor(userService: UserService);
    changePassword(payload: ChangePasswordDto, user: AuthenticatedUser): Promise<{
        message: string;
    }>;
}
//# sourceMappingURL=user.controller.d.ts.map