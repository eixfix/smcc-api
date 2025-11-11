import { ConfigService } from '@nestjs/config';
import type { Role } from '@prisma/client';
import { Strategy } from 'passport-jwt';
import type { AuthenticatedUser } from '../../../common/types/auth-user';
declare const JwtStrategy_base: new (...args: [opt: import("passport-jwt").StrategyOptionsWithoutRequest] | [opt: import("passport-jwt").StrategyOptionsWithRequest]) => Strategy & {
    validate(...args: any[]): unknown;
};
export declare class JwtStrategy extends JwtStrategy_base {
    constructor(configService: ConfigService);
    validate(payload: {
        sub: string;
        email: string;
        role: Role;
    }): Promise<AuthenticatedUser>;
}
export {};
//# sourceMappingURL=jwt.strategy.d.ts.map