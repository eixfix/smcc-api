import { UptimeProtocol, UptimeSensitivity } from '@prisma/client';
export declare class CreateUptimeTargetDto {
    label: string;
    url: string;
    protocol?: UptimeProtocol;
    region?: string;
    sensitivity?: UptimeSensitivity;
    checkIntervalSeconds?: number;
    requestTimeoutMs?: number;
    expectedStatus?: number;
    projectId?: string;
    serverId?: string;
    alertWebhookUrl?: string;
    isPaused?: boolean;
}
//# sourceMappingURL=create-uptime-target.dto.d.ts.map