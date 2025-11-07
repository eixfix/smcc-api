import { JwtService } from '@nestjs/jwt';
import type { Role, User } from '@prisma/client';
import { UserService } from '../user/user.service';
type SanitizedUser = Pick<User, 'id' | 'email' | 'name' | 'role'> & {
    role: Role;
};
export declare class AuthService {
    private readonly usersService;
    private readonly jwtService;
    constructor(usersService: UserService, jwtService: JwtService);
    validateUser(email: string, password: string): Promise<SanitizedUser>;
    login(user: SanitizedUser): Promise<{
        accessToken: string;
        user: SanitizedUser;
    }>;
    profile(userId: string): Promise<SanitizedUser>;
}
export {};
//# sourceMappingURL=auth.service.d.ts.map