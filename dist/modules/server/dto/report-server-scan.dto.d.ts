import { ServerScanStatus } from '@prisma/client';
export declare class ReportServerScanDto {
    status: ServerScanStatus;
    failureReason?: string;
    summary?: Record<string, unknown>;
    rawLog?: string;
    storageMetrics?: Record<string, unknown>;
    memoryMetrics?: Record<string, unknown>;
    securityFindings?: Record<string, unknown>;
}
//# sourceMappingURL=report-server-scan.dto.d.ts.map