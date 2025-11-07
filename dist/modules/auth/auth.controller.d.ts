import type { Role } from '@prisma/client';
import type { Request } from 'express';
import { AuthService } from './auth.service';
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
export declare class AuthController {
    private readonly authService;
    constructor(authService: AuthService);
    login(req: LocalAuthenticatedRequest): Promise<{
        accessToken: string;
        user: Pick<{
            email: string;
            role: import(".prisma/client").$Enums.Role;
            id: string;
            createdAt: Date;
            updatedAt: Date;
            name: string;
            passwordHash: string;
        }, "email" | "role" | "id" | "name"> & {
            role: Role;
        };
    }>;
    getProfile(req: AuthenticatedRequest): Promise<Pick<{
        email: string;
        role: import(".prisma/client").$Enums.Role;
        id: string;
        createdAt: Date;
        updatedAt: Date;
        name: string;
        passwordHash: string;
    }, "email" | "role" | "id" | "name"> & {
        role: Role;
    }>;
}
export {};
//# sourceMappingURL=auth.controller.d.ts.map