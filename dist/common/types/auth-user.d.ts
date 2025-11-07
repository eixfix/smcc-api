import type { Role } from '@prisma/client';
export interface AuthenticatedUser {
    userId: string;
    email: string;
    role: Role;
}
//# sourceMappingURL=auth-user.d.ts.map