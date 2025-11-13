"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ServerAgentInstallController = void 0;
const common_1 = require("@nestjs/common");
const config_1 = require("@nestjs/config");
const jwt_1 = require("@nestjs/jwt");
const client_1 = require("@prisma/client");
const node_crypto_1 = require("node:crypto");
const public_decorator_1 = require("../../common/decorators/public.decorator");
const roles_decorator_1 = require("../../common/decorators/roles.decorator");
const current_user_decorator_1 = require("../../common/decorators/current-user.decorator");
const prisma_service_1 = require("../../prisma/prisma.service");
const server_service_1 = require("./server.service");
const ip_utils_1 = require("../../common/utils/ip.utils");
const agent_bootstrap_template_1 = require("./templates/agent-bootstrap.template");
let ServerAgentInstallController = class ServerAgentInstallController {
    constructor(configService, jwtService, prisma, serverService) {
        this.configService = configService;
        this.jwtService = jwtService;
        this.prisma = prisma;
        this.serverService = serverService;
    }
    async createInstallLink(serverId, user) {
        var _a;
        await this.serverService.ensureServerOwnerAccess(serverId, user);
        const ttlMinutes = Number(this.configService.get('AGENT_INSTALL_TOKEN_TTL_MINUTES')) || 60;
        const secret = this.configService.get('AGENT_INSTALL_TOKEN_SECRET') ||
            this.configService.get('JWT_SECRET');
        const nonce = (0, node_crypto_1.randomBytes)(16).toString('base64url');
        const token = await this.jwtService.signAsync({
            type: 'install-script',
            serverId,
            nonce
        }, {
            secret,
            expiresIn: `${ttlMinutes}m`
        });
        const publicUrl = ((_a = this.configService.get('API_PUBLIC_URL')) !== null && _a !== void 0 ? _a : '').replace(/\/$/, '');
        const installUrl = `${publicUrl}/agents/install.sh/${token}`;
        return {
            installUrl,
            command: `curl -fsSL ${installUrl} | sudo bash`,
            expiresInMinutes: ttlMinutes,
            nonce
        };
    }
    async getInstallScript(token, request) {
        return this.buildInstallerScript(token, request, { skipConfigRewrite: false });
    }
    async getUpdateScript(token, request) {
        return this.buildInstallerScript(token, request, { skipConfigRewrite: true });
    }
    async getUpdateScriptWithoutToken(serverId, request) {
        return this.buildInstallerScriptForServer(serverId, request, { skipConfigRewrite: true });
    }
    async buildInstallerScript(token, request, options) {
        var _a;
        const secret = this.configService.get('AGENT_INSTALL_TOKEN_SECRET') ||
            this.configService.get('JWT_SECRET');
        let payload;
        try {
            payload = await this.jwtService.verifyAsync(token, { secret });
        }
        catch {
            throw new common_1.UnauthorizedException('Invalid or expired installer token.');
        }
        if (payload.type !== 'install-script') {
            throw new common_1.UnauthorizedException('Invalid installer token.');
        }
        const server = await this.prisma.server.findUnique({
            where: { id: payload.serverId },
            select: {
                id: true,
                allowedIp: true
            }
        });
        if (!server) {
            throw new common_1.NotFoundException('Server not found.');
        }
        const allowedIp = (0, ip_utils_1.normalizeIp)(server.allowedIp);
        const clientIp = (0, ip_utils_1.normalizeIp)((0, ip_utils_1.extractClientIp)(request));
        if (!allowedIp || allowedIp !== clientIp) {
            throw new common_1.ForbiddenException('Installer can only be accessed from the registered server IP.');
        }
        const installNonce = (_a = payload.nonce) !== null && _a !== void 0 ? _a : (0, node_crypto_1.randomBytes)(12).toString('base64url');
        return this.renderInstallerScript(server.id, installNonce, options);
    }
    async buildInstallerScriptForServer(serverId, request, options) {
        const server = await this.prisma.server.findUnique({
            where: { id: serverId },
            select: {
                id: true,
                allowedIp: true
            }
        });
        if (!server) {
            throw new common_1.NotFoundException('Server not found.');
        }
        const allowedIp = (0, ip_utils_1.normalizeIp)(server.allowedIp);
        const clientIp = (0, ip_utils_1.normalizeIp)((0, ip_utils_1.extractClientIp)(request));
        if (!allowedIp || allowedIp !== clientIp) {
            throw new common_1.ForbiddenException('Installer can only be accessed from the registered server IP.');
        }
        const installNonce = (0, node_crypto_1.randomBytes)(12).toString('base64url');
        return this.renderInstallerScript(server.id, installNonce, options);
    }
    renderInstallerScript(serverId, installNonce, options) {
        var _a, _b, _c, _d, _e, _f, _g, _h, _j, _k, _l;
        const serviceName = (_a = this.configService.get('AGENT_SYSTEMD_SERVICE')) !== null && _a !== void 0 ? _a : 'loadtest-agent';
        const installDir = (_b = this.configService.get('AGENT_INSTALL_DIR')) !== null && _b !== void 0 ? _b : '$HOME/loadtest-agent';
        const binPath = (_c = this.configService.get('AGENT_BINARY_PATH')) !== null && _c !== void 0 ? _c : '/usr/local/bin/loadtest-agent';
        const configPath = (_d = this.configService.get('AGENT_CONFIG_PATH')) !== null && _d !== void 0 ? _d : '/etc/loadtest-agent/config.yaml';
        const apiPublicUrl = (_e = this.configService.get('API_PUBLIC_URL')) !== null && _e !== void 0 ? _e : 'https://api.loadtest.dev';
        const agentVersion = (_f = this.configService.get('AGENT_SCRIPT_VERSION')) !== null && _f !== void 0 ? _f : '1.0.0';
        const defaultUpdateIntervalMinutes = Number(this.configService.get('AGENT_DEFAULT_UPDATE_INTERVAL_MINUTES')) || 60;
        const configSignatureKey = (_h = (_g = this.configService.get('AGENT_CONFIG_SIGNATURE_KEY')) !== null && _g !== void 0 ? _g : this.configService.get('AGENT_PAYLOAD_KEY')) !== null && _h !== void 0 ? _h : '';
        const updateSignatureKey = (_j = this.configService.get('AGENT_UPDATE_SIGNATURE_KEY')) !== null && _j !== void 0 ? _j : configSignatureKey;
        const configRefreshIntervalMinutes = Number(this.configService.get('AGENT_CONFIG_REFRESH_INTERVAL_MINUTES')) || 360;
        const playbookConfigPath = (_k = this.configService.get('AGENT_PLAYBOOK_CONFIG_PATH')) !== null && _k !== void 0 ? _k : '/etc/smcc-agent/playbooks.json';
        const playbookTimeoutSeconds = Number(this.configService.get('AGENT_PLAYBOOK_TIMEOUT_SECONDS')) || 600;
        const metadataPath = (_l = this.configService.get('AGENT_METADATA_PATH')) !== null && _l !== void 0 ? _l : `${configPath}.meta.json`;
        const derivedKey = (0, node_crypto_1.randomBytes)(32).toString('base64');
        const serviceUnitPath = `/etc/systemd/system/${serviceName}.service`;
        const installDirEscaped = installDir.replace(/"/g, '\\"');
        const binPathEscaped = binPath.replace(/"/g, '\\"');
        const configPathEscaped = configPath.replace(/"/g, '\\"');
        const metadataPathEscaped = metadataPath.replace(/"/g, '\\"');
        const playbookPathEscaped = playbookConfigPath.replace(/"/g, '\\"');
        const agentScript = (0, agent_bootstrap_template_1.buildAgentBootstrapTemplate)({
            apiUrl: apiPublicUrl,
            configPath,
            metadataPath,
            binaryPath: binPath,
            agentVersion,
            defaultUpdateIntervalMinutes,
            derivedKey,
            installNonce,
            logPrefix: serviceName,
            configSignatureKey,
            updateSignatureKey,
            configRefreshIntervalMinutes,
            playbookConfigPath,
            playbookTimeoutSeconds
        });
        const skipConfigRewriteFlag = options.skipConfigRewrite ? '1' : '0';
        const postInstallMessage = options.skipConfigRewrite
            ? '[loadtest] Agent updated. Existing credentials preserved.'
            : '[loadtest] Agent installed. Update $CONFIG_PATH with real credentials before restarting.';
        return `#!/usr/bin/env bash
set -euo pipefail
: "\${HOME:=/root}"

echo "[loadtest] Installing agent files..."
INSTALL_DIR="${installDirEscaped}"
BIN_PATH="${binPathEscaped}"
CONFIG_PATH="${configPathEscaped}"
METADATA_PATH="${metadataPathEscaped}"
PLAYBOOKS_PATH="${playbookPathEscaped}"
SERVICE_NAME="${serviceName}"
SERVICE_PATH="${serviceUnitPath}"
SKIP_CONFIG_REWRITE="${skipConfigRewriteFlag}"

mkdir -p "$INSTALL_DIR"

cat <<'LOADTEST_AGENT_SOURCE' > "$INSTALL_DIR/loadtest-agent.js"
${agentScript}
LOADTEST_AGENT_SOURCE

install -m 755 "$INSTALL_DIR/loadtest-agent.js" "$BIN_PATH"
install -d -m 755 "$(dirname "$CONFIG_PATH")"
install -d -m 755 "$(dirname "$METADATA_PATH")"
install -d -m 755 "$(dirname "$PLAYBOOKS_PATH")"

if [ "\${SKIP_CONFIG_REWRITE}" != "1" ]; then
LT_AGENT_CONFIG_PATH="$CONFIG_PATH" \
LT_AGENT_METADATA_PATH="$METADATA_PATH" \
LT_AGENT_DERIVED_KEY="${derivedKey}" \
LT_AGENT_INSTALL_NONCE="${installNonce}" \
LT_AGENT_VERSION="${agentVersion}" \
LT_AGENT_SERVER_ID="${serverId}" \
LT_AGENT_API_URL="${apiPublicUrl}" \
LT_AGENT_POLL_INTERVAL="30" \
LT_AGENT_TELEMETRY_INTERVAL="60" \
LT_AGENT_UPDATE_INTERVAL="${defaultUpdateIntervalMinutes}" \
node <<'LOADTEST_ENCRYPT_CONFIG'
const crypto = require('node:crypto');
const fs = require('node:fs');

const configPath = process.env.LT_AGENT_CONFIG_PATH;
const metadataPath = process.env.LT_AGENT_METADATA_PATH;
const derivedKeyB64 = process.env.LT_AGENT_DERIVED_KEY;
const installNonce = process.env.LT_AGENT_INSTALL_NONCE || '';
const agentVersion = process.env.LT_AGENT_VERSION || 'unknown';

const derivedKey = Buffer.from(derivedKeyB64, 'base64');

const metadata = {
  install_nonce: installNonce,
  derived_key: derivedKeyB64,
  generated_at: new Date().toISOString(),
  script_version: agentVersion
};

fs.writeFileSync(metadataPath, JSON.stringify(metadata, null, 2), { mode: 0o600 });

function encrypt(key, buffer) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(buffer), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    algorithm: 'aes-256-gcm',
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
    data: ciphertext.toString('base64')
  };
}

const dataKey = crypto.randomBytes(32);
const configPayload = {
  serverId: process.env.LT_AGENT_SERVER_ID,
  accessKey: '<access-key>',
  secret: '<secret>',
  apiUrl: process.env.LT_AGENT_API_URL,
  pollIntervalSeconds: Number(process.env.LT_AGENT_POLL_INTERVAL || '30'),
  telemetryIntervalMinutes: Number(process.env.LT_AGENT_TELEMETRY_INTERVAL || '60'),
  updateIntervalMinutes: Number(process.env.LT_AGENT_UPDATE_INTERVAL || '60'),
  logLevel: 'info',
  agentVersion: process.env.LT_AGENT_VERSION || '${agentVersion}'
};

const document = {
  version: 2,
  encryptedConfig: encrypt(dataKey, Buffer.from(JSON.stringify(configPayload), 'utf8')),
  wrappedKey: encrypt(derivedKey, dataKey)
};

fs.writeFileSync(configPath, JSON.stringify(document, null, 2), { mode: 0o600 });
LOADTEST_ENCRYPT_CONFIG
else
  echo "[loadtest] Skipping config rewrite (update mode)."
fi

if [ ! -f "$PLAYBOOKS_PATH" ]; then
cat <<'LOADTEST_SAMPLE_PLAYBOOKS' > "$PLAYBOOKS_PATH"
{
  "baseline-security": {
    "command": "/usr/local/bin/smcc-baseline.sh",
    "args": [
      "--target",
      "example.internal"
    ],
    "timeoutSeconds": 300
  },
  "checkout-smoke": {
    "command": "k6",
    "args": [
      "run",
      "/opt/loadtests/checkout-smoke.js"
    ],
    "timeoutSeconds": 180
  }
}
LOADTEST_SAMPLE_PLAYBOOKS
  chmod 600 "$PLAYBOOKS_PATH"
  echo "[loadtest] Sample playbook definitions written to $PLAYBOOKS_PATH. Update commands before running."
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

echo "${postInstallMessage}"
`;
    }
    buildAgentSource(apiUrl, configPath, agentVersion, defaultUpdateIntervalMinutes, binaryPath) {
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
};
exports.ServerAgentInstallController = ServerAgentInstallController;
__decorate([
    (0, roles_decorator_1.Roles)(client_1.Role.ADMINISTRATOR, client_1.Role.OWNER),
    (0, common_1.Post)('servers/:serverId/install-link'),
    __param(0, (0, common_1.Param)('serverId')),
    __param(1, (0, current_user_decorator_1.CurrentUser)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object]),
    __metadata("design:returntype", Promise)
], ServerAgentInstallController.prototype, "createInstallLink", null);
__decorate([
    (0, public_decorator_1.Public)(),
    (0, common_1.Get)('agents/install.sh/:token'),
    (0, common_1.Header)('Content-Type', 'text/x-shellscript'),
    __param(0, (0, common_1.Param)('token')),
    __param(1, (0, common_1.Req)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object]),
    __metadata("design:returntype", Promise)
], ServerAgentInstallController.prototype, "getInstallScript", null);
__decorate([
    (0, public_decorator_1.Public)(),
    (0, common_1.Get)('agents/update.sh/:token'),
    (0, common_1.Header)('Content-Type', 'text/x-shellscript'),
    __param(0, (0, common_1.Param)('token')),
    __param(1, (0, common_1.Req)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object]),
    __metadata("design:returntype", Promise)
], ServerAgentInstallController.prototype, "getUpdateScript", null);
__decorate([
    (0, public_decorator_1.Public)(),
    (0, common_1.Get)('agents/:serverId/update.sh'),
    (0, common_1.Header)('Content-Type', 'text/x-shellscript'),
    __param(0, (0, common_1.Param)('serverId')),
    __param(1, (0, common_1.Req)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object]),
    __metadata("design:returntype", Promise)
], ServerAgentInstallController.prototype, "getUpdateScriptWithoutToken", null);
exports.ServerAgentInstallController = ServerAgentInstallController = __decorate([
    (0, common_1.Controller)(),
    __metadata("design:paramtypes", [config_1.ConfigService,
        jwt_1.JwtService,
        prisma_service_1.PrismaService,
        server_service_1.ServerService])
], ServerAgentInstallController);
//# sourceMappingURL=server-agent-install.controller.js.map