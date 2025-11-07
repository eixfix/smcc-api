import { HttpException } from '@nestjs/common';
import type { Prisma } from '@prisma/client';
import { PrismaService } from '../../prisma/prisma.service';
export declare class InsufficientCreditsException extends HttpException {
    constructor(required: number, context?: string);
}
export declare class OrganizationCreditService {
    private readonly prisma;
    constructor(prisma: PrismaService);
    spendCredits(organizationId: string, amount: number, tx?: Prisma.TransactionClient, context?: string): Promise<void>;
    addCredits(organizationId: string, amount: number, tx?: Prisma.TransactionClient): Promise<number>;
    refundCredits(organizationId: string, amount: number): Promise<void>;
    private resolveClient;
    debitForServerScan(organizationId: string, tx?: Prisma.TransactionClient): Promise<void>;
    debitForTelemetry(organizationId: string, tx?: Prisma.TransactionClient): Promise<void>;
}
//# sourceMappingURL=organization-credit.service.d.ts.map