import { Strategy } from 'passport-local';
import { AuthService } from '../auth.service';
declare const LocalStrategy_base: new (...args: [] | [options: import("passport-local").IStrategyOptionsWithRequest] | [options: import("passport-local").IStrategyOptions]) => Strategy & {
    validate(...args: any[]): unknown;
};
export declare class LocalStrategy extends LocalStrategy_base {
    private readonly authService;
    constructor(authService: AuthService);
    validate(email: string, password: string): Promise<Pick<{
        email: string;
        role: import(".prisma/client").$Enums.Role;
        id: string;
        createdAt: Date;
        updatedAt: Date;
        name: string;
        passwordHash: string;
    }, "email" | "role" | "id" | "name"> & {
        role: import(".prisma/client").Role;
    }>;
}
export {};
//# sourceMappingURL=local.strategy.d.ts.map