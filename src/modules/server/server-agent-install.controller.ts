import {
  Controller,
  ForbiddenException,
  Get,
  Header,
  NotFoundException,
  Param,
  Post,
  Req,
  UnauthorizedException,
  UseGuards
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { Role } from '@prisma/client';
import type { Request } from 'express';

import { Public } from '../../common/decorators/public.decorator';
import { Roles } from '../../common/decorators/roles.decorator';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import type { AuthenticatedUser } from '../../common/types/auth-user';
import { PrismaService } from '../../prisma/prisma.service';
import { ServerService } from './server.service';
import { extractClientIp, normalizeIp } from '../../common/utils/ip.utils';
import { CurrentAgent } from './decorators/current-agent.decorator';
import { AgentSessionGuard } from './guards/agent-session.guard';
import type { AgentSessionContext } from './guards/agent-session.guard';

@Controller()
export class ServerAgentInstallController {
  constructor(
    private readonly configService: ConfigService,
    private readonly jwtService: JwtService,
    private readonly prisma: PrismaService,
    private readonly serverService: ServerService
  ) {}

  @Roles(Role.ADMINISTRATOR, Role.OWNER)
  @Post('servers/:serverId/install-link')
  async createInstallLink(
    @Param('serverId') serverId: string,
    @CurrentUser() user: AuthenticatedUser
  ) {
    await this.serverService.ensureServerOwnerAccess(serverId, user);

    const ttlMinutes =
      Number(this.configService.get<string>('AGENT_INSTALL_TOKEN_TTL_MINUTES')) || 60;
    const secret =
      this.configService.get<string>('AGENT_INSTALL_TOKEN_SECRET') ||
      this.configService.get<string>('JWT_SECRET');

    const token = await this.jwtService.signAsync(
      {
        type: 'install-script',
        serverId
      },
      {
        secret,
        expiresIn: `${ttlMinutes}m`
      }
    );

    const publicUrl = (this.configService.get<string>('API_PUBLIC_URL') ?? '').replace(
      /\/$/,
      ''
    );
    const installUrl = `${publicUrl}/agents/install.sh/${token}`;

    return {
      installUrl,
      command: `curl -fsSL ${installUrl} | sudo bash`,
      expiresInMinutes: ttlMinutes
    };
  }

  @Public()
  @Get('agents/install.sh/:token')
  @Header('Content-Type', 'text/x-shellscript')
  async getInstallScript(@Param('token') token: string, @Req() request: Request): Promise<string> {
    const secret =
      this.configService.get<string>('AGENT_INSTALL_TOKEN_SECRET') ||
      this.configService.get<string>('JWT_SECRET');

    let payload: { type: string; serverId: string };

    try {
      payload = await this.jwtService.verifyAsync(token, { secret });
    } catch {
      throw new UnauthorizedException('Invalid or expired installer token.');
    }

    if (payload.type !== 'install-script') {
      throw new UnauthorizedException('Invalid installer token.');
    }

    const server = await this.prisma.server.findUnique({
      where: { id: payload.serverId },
      select: {
        id: true,
        allowedIp: true
      }
    });

    if (!server) {
      throw new NotFoundException('Server not found.');
    }

    const allowedIp = normalizeIp(server.allowedIp);
    const clientIp = normalizeIp(extractClientIp(request));

    if (!allowedIp || allowedIp !== clientIp) {
      throw new ForbiddenException('Installer can only be accessed from the registered server IP.');
    }

    const serviceName =
      this.configService.get<string>('AGENT_SYSTEMD_SERVICE') ?? 'loadtest-agent';
    const installDir =
      this.configService.get<string>('AGENT_INSTALL_DIR') ?? '$HOME/loadtest-agent';
    const binPath =
      this.configService.get<string>('AGENT_BINARY_PATH') ?? '/usr/local/bin/loadtest-agent';
    const configPath =
      this.configService.get<string>('AGENT_CONFIG_PATH') ?? '/etc/loadtest-agent/config.yaml';
    const apiPublicUrl =
      this.configService.get<string>('API_PUBLIC_URL') ?? 'https://api.loadtest.dev';
    const agentVersion =
      this.configService.get<string>('AGENT_SCRIPT_VERSION') ?? '1.0.0';
    const defaultUpdateIntervalMinutes =
      Number(this.configService.get<string>('AGENT_DEFAULT_UPDATE_INTERVAL_MINUTES')) || 60;

    const serviceUnitPath = `/etc/systemd/system/${serviceName}.service`;
    const installDirEscaped = installDir.replace(/"/g, '\\"');
    const binPathEscaped = binPath.replace(/"/g, '\\"');
    const configPathEscaped = configPath.replace(/"/g, '\\"');
    const agentScript = this.buildAgentSource(
      apiPublicUrl,
      configPath,
      agentVersion,
      defaultUpdateIntervalMinutes,
      binPath
    );

    return `#!/usr/bin/env bash
set -euo pipefail

echo "[loadtest] Installing agent files..."
INSTALL_DIR="${installDirEscaped}"
BIN_PATH="${binPathEscaped}"
CONFIG_PATH="${configPathEscaped}"
SERVICE_NAME="${serviceName}"
SERVICE_PATH="${serviceUnitPath}"

mkdir -p "$INSTALL_DIR"

cat <<'LOADTEST_AGENT_SOURCE' > "$INSTALL_DIR/loadtest-agent.js"
${agentScript}
LOADTEST_AGENT_SOURCE

install -m 755 "$INSTALL_DIR/loadtest-agent.js" "$BIN_PATH"
install -d -m 755 "$(dirname "$CONFIG_PATH")"
if [ ! -f "$CONFIG_PATH" ]; then
  cat <<'EOF' > "$CONFIG_PATH"
server_id: "${server.id}"
agent_access_key: "<access-key>"
agent_secret: "<secret>"
api_url: "${apiPublicUrl}"
poll_interval_seconds: 30
telemetry_interval_minutes: 60
update_interval_minutes: ${defaultUpdateIntervalMinutes}
log_level: info
EOF
  chmod 600 "$CONFIG_PATH"
fi

cat <<EOF > "$SERVICE_PATH"
[Unit]
Description=LoadTest Agent
After=network.target

[Service]
Type=simple
ExecStart=${binPathEscaped}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now "$SERVICE_NAME"

echo "[loadtest] Agent installed. Update $CONFIG_PATH with real credentials before restarting."
`;
  }

  @Public()
  @UseGuards(AgentSessionGuard)
  @Get('agent/script')
  getAgentScript(@CurrentAgent() _agent: AgentSessionContext) {
    const apiPublicUrl =
      this.configService.get<string>('API_PUBLIC_URL') ?? 'https://api.loadtest.dev';
    const configPath =
      this.configService.get<string>('AGENT_CONFIG_PATH') ?? '/etc/loadtest-agent/config.yaml';
    const agentVersion =
      this.configService.get<string>('AGENT_SCRIPT_VERSION') ?? '1.0.0';
    const defaultUpdateIntervalMinutes =
      Number(this.configService.get<string>('AGENT_DEFAULT_UPDATE_INTERVAL_MINUTES')) || 60;
    const binPath =
      this.configService.get<string>('AGENT_BINARY_PATH') ?? '/usr/local/bin/loadtest-agent';

    return {
      version: agentVersion,
      source: this.buildAgentSource(
        apiPublicUrl,
        configPath,
        agentVersion,
        defaultUpdateIntervalMinutes,
        binPath
      )
    };
  }

  private buildAgentSource(
    apiUrl: string,
    configPath: string,
    agentVersion: string,
    defaultUpdateIntervalMinutes: number,
    binaryPath: string
  ): string {
    const escapedApiUrl = apiUrl.replace(/\\/g, '\\\\').replace(/`/g, '\\`');
    const escapedConfigPath = configPath.replace(/\\/g, '\\\\').replace(/`/g, '\\`');
    const escapedBinaryPath = binaryPath.replace(/\\/g, '\\\\').replace(/`/g, '\\`');

    return `#!/usr/bin/env node
const fs = require('node:fs');
const os = require('node:os');

const DEFAULT_CONFIG_PATH = process.env.LOADTEST_AGENT_CONFIG ?? '${escapedConfigPath}';
const DEFAULT_API_URL = '${escapedApiUrl}';
const AGENT_VERSION = '${agentVersion}';
const AGENT_FILE_PATH = process.env.LOADTEST_AGENT_BINARY_PATH ?? '${escapedBinaryPath}';
const DEFAULT_UPDATE_INTERVAL_MINUTES = ${defaultUpdateIntervalMinutes};

function parseConfig(filePath) {
  if (!fs.existsSync(filePath)) {
    throw new Error(\`Config file not found at \${filePath}\`);
  }

  const content = fs.readFileSync(filePath, 'utf8');
  const config = {};

  for (const line of content.split(/\\r?\\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) {
      continue;
    }
    const separatorIndex = trimmed.indexOf(':');
    if (separatorIndex === -1) {
      continue;
    }
    const key = trimmed.slice(0, separatorIndex).trim();
    const value = trimmed.slice(separatorIndex + 1).trim().replace(/^['"]|['"]$/g, '');
    config[key] = value;
  }

  return config;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function authenticate(config, apiBaseUrl) {
  const response = await fetch(\`\${apiBaseUrl}/agent/auth\`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      serverId: config.server_id,
      accessKey: config.agent_access_key,
      secret: config.agent_secret
    })
  });

  if (!response.ok) {
    throw new Error(\`Agent auth failed: \${response.status}\`);
  }

  return response.json();
}

async function fetchLatestAgent(apiBaseUrl, token) {
  const response = await fetch(\`\${apiBaseUrl}/agent/script\`, {
    headers: {
      Authorization: \`Bearer \${token}\`
    }
  });

  if (!response.ok) {
    return null;
  }

  return response.json();
}

async function attemptSelfUpdate(apiBaseUrl, token) {
  const manifest = await fetchLatestAgent(apiBaseUrl, token);
  if (!manifest || manifest.version === AGENT_VERSION || !manifest.source) {
    return false;
  }

  fs.writeFileSync(AGENT_FILE_PATH, manifest.source, { mode: 0o755 });
  console.log(\`[loadtest-agent] Updated to version \${manifest.version}. Restarting...\`);
  return true;
}

async function fetchNextScan(apiBaseUrl, token) {
  const response = await fetch(\`\${apiBaseUrl}/agent/scans/next\`, {
    method: 'POST',
    headers: {
      Authorization: \`Bearer \${token}\`
    }
  });

  if (response.status === 204) {
    return null;
  }

  if (!response.ok) {
    throw new Error(\`Failed to fetch next scan: \${response.status}\`);
  }

  return response.json();
}

async function reportScanFailure(apiBaseUrl, token, scanId, reason) {
  await fetch(\`\${apiBaseUrl}/agent/scans/\${scanId}/report\`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: \`Bearer \${token}\`
    },
    body: JSON.stringify({
      status: 'FAILED',
      failureReason: reason,
      summary: {
        note: 'Reference agent installation script does not execute playbooks. Replace with production agent.'
      }
    })
  });
}

async function sendTelemetry(apiBaseUrl, token, config) {
  const payload = {
    serverId: config.server_id,
    hostname: os.hostname(),
    platform: os.platform(),
    uptimeSeconds: Math.round(os.uptime()),
    loadAverage: os.loadavg(),
    freeMemBytes: os.freemem(),
    totalMemBytes: os.totalmem()
  };

  await fetch(\`\${apiBaseUrl}/agent/telemetry\`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: \`Bearer \${token}\`
    },
    body: JSON.stringify(payload)
  });
}

async function main() {
  const config = parseConfig(DEFAULT_CONFIG_PATH);
  const pollIntervalMs = Math.max(5, Number(config.poll_interval_seconds ?? 30)) * 1000;
  const telemetryIntervalMs = Math.max(1, Number(config.telemetry_interval_minutes ?? 60)) * 60 * 1000;
  const updateIntervalMs =
    Math.max(10, Number(config.update_interval_minutes ?? DEFAULT_UPDATE_INTERVAL_MINUTES)) *
    60 *
    1000;
  const apiBaseUrl = (config.api_url ?? DEFAULT_API_URL).replace(/\\/$/, '');

  console.log('[loadtest-agent] Starting agent loop');
  let sessionToken = null;
  let tokenExpiresAt = 0;
  let lastTelemetryAt = 0;
  let lastUpdateCheckAt = 0;

  while (true) {
    try {
      if (!sessionToken || Date.now() >= tokenExpiresAt - 60_000) {
        console.log('[loadtest-agent] Authenticating with API');
        const session = await authenticate(config, apiBaseUrl);
        sessionToken = session.sessionToken;
        tokenExpiresAt = Date.now() + session.expiresInSeconds * 1000;
      }

      if (Date.now() - lastTelemetryAt >= telemetryIntervalMs) {
        await sendTelemetry(apiBaseUrl, sessionToken, config);
        lastTelemetryAt = Date.now();
        console.log('[loadtest-agent] Telemetry sent');
      }

      if (Date.now() - lastUpdateCheckAt >= updateIntervalMs) {
        lastUpdateCheckAt = Date.now();
        const updated = await attemptSelfUpdate(apiBaseUrl, sessionToken);
        if (updated) {
          await sleep(2000);
          process.exit(0);
        }
      }

      const job = await fetchNextScan(apiBaseUrl, sessionToken);

      if (job) {
        console.log(\`[loadtest-agent] Received scan job \${job.id}, marking as failed placeholder\`);
        await reportScanFailure(
          apiBaseUrl,
          sessionToken,
          job.id,
          'Reference agent does not execute playbooks.'
        );
      } else {
        await sleep(pollIntervalMs);
      }
    } catch (error) {
      console.error('[loadtest-agent] Error:', error.message);
      sessionToken = null;
      await sleep(Math.min(pollIntervalMs, 10_000));
    }
  }
}

main().catch((error) => {
  console.error('[loadtest-agent] Fatal error:', error);
  process.exit(1);
});
`;
  }
}
