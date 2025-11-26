import { UptimeReason, UptimeSensitivity, UptimeState } from '@prisma/client';
export interface TargetNotificationContext {
    id: string;
    label: string;
    url: string;
    region?: string | null;
    sensitivity: UptimeSensitivity;
    alertWebhookUrl?: string | null;
    organization: {
        id: string;
        name: string;
        uptimeWebhookUrl?: string | null;
    };
    project?: {
        id: string;
        name: string;
        uptimeWebhookUrl?: string | null;
    } | null;
}
export interface SnapshotNotificationContext {
    state: UptimeState;
    reason: UptimeReason;
    reasonDetail?: string | null;
    since: Date;
}
export interface CheckNotificationContext {
    statusCode?: number | null;
    latencyMs?: number | null;
    tlsExpiresAt?: Date | null;
    checkedAt: Date;
}
export declare class UptimeNotifierService {
    private readonly logger;
    sendStateChange(target: TargetNotificationContext, snapshot: SnapshotNotificationContext, check: CheckNotificationContext, previousStateDurationMs: number): Promise<void>;
    sendDigest(webhookUrl: string, organizationName: string, targets: Array<{
        label: string;
        url: string;
        state: UptimeState;
        reason: UptimeReason;
        reasonDetail?: string | null;
        since: Date;
    }>): Promise<void>;
    sendTest(webhookUrl: string, label: string, payload: TestNotificationPayload): Promise<void>;
    private resolveWebhook;
    private resolveStateColor;
    private formatDuration;
    private sendWebhook;
}
interface TestNotificationPayload {
    state?: UptimeState;
    reason?: UptimeReason;
    reasonDetail?: string;
}
export {};
//# sourceMappingURL=uptime-notifier.service.d.ts.map