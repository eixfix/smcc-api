import type { AuthenticatedUser } from '../../common/types/auth-user';
import { CheckEndpointDto } from './dto/check-endpoint.dto';
import { SecurityService } from './security.service';
export declare class SecurityController {
    private readonly securityService;
    constructor(securityService: SecurityService);
    checkEndpoint(payload: CheckEndpointDto, user: AuthenticatedUser): Promise<import("./types").SecurityCheckResult>;
}
//# sourceMappingURL=security.controller.d.ts.map