import { Injectable, Logger } from '@nestjs/common';
import { UptimeReason, UptimeSensitivity, UptimeState } from '@prisma/client';

export interface TargetNotificationContext {
  id: string;
  label: string;
  url: string;
  region?: string | null;
  sensitivity: UptimeSensitivity;
  alertWebhookUrl?: string | null;
  organization: { id: string; name: string; uptimeWebhookUrl?: string | null };
  project?: { id: string; name: string; uptimeWebhookUrl?: string | null } | null;
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

@Injectable()
export class UptimeNotifierService {
  private readonly logger = new Logger(UptimeNotifierService.name);

  async sendStateChange(
    target: TargetNotificationContext,
    snapshot: SnapshotNotificationContext,
    check: CheckNotificationContext,
    previousStateDurationMs: number
  ): Promise<void> {
    const webhookUrl = this.resolveWebhook(target);

    if (!webhookUrl) {
      return;
    }

    const payload = {
      content: `⚠️ Uptime update for ${target.label}`,
      embeds: [
        {
          title: `${snapshot.state} – ${target.url}`,
          description: snapshot.reasonDetail ?? snapshot.reason,
          color: this.resolveStateColor(snapshot.state),
          fields: [
            { name: 'State', value: snapshot.state, inline: true },
            snapshot.reasonDetail
              ? { name: 'Detail', value: snapshot.reasonDetail, inline: true }
              : null,
            {
              name: 'Latency',
              value: check.latencyMs ? `${check.latencyMs} ms` : 'n/a',
              inline: true
            },
            {
              name: 'Status Code',
              value: check.statusCode ? check.statusCode.toString() : 'n/a',
              inline: true
            },
            {
              name: 'Duration In Previous State',
              value: this.formatDuration(previousStateDurationMs),
              inline: true
            },
            {
              name: 'Sensitivity',
              value: target.sensitivity,
              inline: true
            }
          ].filter(Boolean),
          footer: {
            text: `${target.organization.name}${target.project ? ` · ${target.project.name}` : ''}${
              target.region ? ` · ${target.region}` : ''
            }`
          },
          timestamp: check.checkedAt.toISOString()
        }
      ]
    };

    await this.sendWebhook(webhookUrl, payload, 'state-change');
  }

  async sendDigest(
    webhookUrl: string,
    organizationName: string,
    targets: Array<{
      label: string;
      url: string;
      state: UptimeState;
      reason: UptimeReason;
      reasonDetail?: string | null;
      since: Date;
    }>
  ): Promise<void> {
    if (!targets.length) {
      return;
    }

    const counts = targets.reduce(
      (acc, target) => {
        acc[target.state] = (acc[target.state] ?? 0) + 1;
        return acc;
      },
      {} as Record<UptimeState, number>
    );

    const lines = targets.slice(0, 20).map((target) => {
      const duration = this.formatDuration(Date.now() - target.since.getTime());
      const reasonText = target.reasonDetail ?? target.reason;
      return `• ${target.label} – ${target.state} (${duration}, ${reasonText})`;
    });

    const payload = {
      content: `🧭 Uptime digest for ${organizationName}`,
      embeds: [
        {
          title: 'Domain summary',
          description: lines.join('\n'),
          fields: [
            { name: 'UP', value: String(counts[UptimeState.UP] ?? 0), inline: true },
            { name: 'DEGRADED', value: String(counts[UptimeState.DEGRADED] ?? 0), inline: true },
            { name: 'DOWN', value: String(counts[UptimeState.DOWN] ?? 0), inline: true }
          ],
          color: 5763719,
          timestamp: new Date().toISOString()
        }
      ]
    };

    await this.sendWebhook(webhookUrl, payload, 'digest');
  }

  async sendTest(webhookUrl: string, label: string, payload: TestNotificationPayload): Promise<void> {
    const content = {
      content: `🔧 Uptime webhook test for ${label}`,
      embeds: [
        {
          title: `${payload.state ?? UptimeState.UP} – ${payload.reason ?? UptimeReason.UNKNOWN}`,
          description: payload.reasonDetail ?? 'Webhook test triggered from dashboard',
          color: this.resolveStateColor(payload.state ?? UptimeState.UP),
          timestamp: new Date().toISOString()
        }
      ]
    };

    await this.sendWebhook(webhookUrl, content, 'test');
  }

  private resolveWebhook(target: TargetNotificationContext): string | null {
    return (
      target.alertWebhookUrl ??
      target.project?.uptimeWebhookUrl ??
      target.organization.uptimeWebhookUrl ??
      null
    );
  }

  private resolveStateColor(state: UptimeState): number {
    switch (state) {
      case UptimeState.UP:
        return 5793266;
      case UptimeState.DEGRADED:
        return 16763904;
      case UptimeState.DOWN:
        return 15548997;
      default:
        return 7506394;
    }
  }

  private formatDuration(durationMs: number): string {
    if (!durationMs || durationMs < 1000) {
      return 'just now';
    }

    const seconds = Math.floor(durationMs / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);

    if (days > 0) {
      return `${days}d ${hours % 24}h`;
    }

    if (hours > 0) {
      return `${hours}h ${minutes % 60}m`;
    }

    if (minutes > 0) {
      return `${minutes}m ${seconds % 60}s`;
    }

    return `${seconds}s`;
  }

  private async sendWebhook(url: string, payload: unknown, type: string): Promise<void> {
    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(payload)
      });

      if (!response.ok) {
        this.logger.warn(`Failed to send ${type} webhook to ${url}: ${response.statusText}`);
      }
    } catch (error) {
      this.logger.error(`Error sending ${type} webhook to ${url}: ${(error as Error).message}`);
    }
  }
}

interface TestNotificationPayload {
  state?: UptimeState;
  reason?: UptimeReason;
  reasonDetail?: string;
}
