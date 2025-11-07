import type { AuthenticatedUser } from '../../common/types/auth-user';
import { PrismaService } from '../../prisma/prisma.service';
import { OrganizationCreditService } from '../organization/organization-credit.service';
import type { SecurityCheckResult } from './types';
export declare class SecurityService {
    private readonly prisma;
    private readonly creditService;
    private readonly logger;
    constructor(prisma: PrismaService, creditService: OrganizationCreditService);
    checkEndpoint(organizationId: string, url: string, user: AuthenticatedUser): Promise<SecurityCheckResult>;
    private ensureUserExists;
    private verifyOrganizationAccess;
    private normalizeUrl;
    private evaluateSecurityHeaders;
    private readLimitedText;
    private extractMetadata;
    private decodeHtmlEntities;
    private sanitizeText;
    private stripMailto;
    private inspectTls;
    private formatCertAttributes;
    private lookupWhois;
    private extractTld;
    private resolveWhoisServer;
    private extractWhoisField;
    private lookupOwnership;
    private normalizeSoaEmail;
    private lookupRdap;
    private normalizeEntities;
    private normalizeEntity;
    private findEntity;
    private extractVcardValue;
    private queryWhois;
}
//# sourceMappingURL=security.service.d.ts.map