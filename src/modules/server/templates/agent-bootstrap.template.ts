const sanitizeLiteral = (value: string): string =>
  value.replace(/\\/g, '\\\\').replace(/`/g, '\\`');

interface AgentBootstrapTemplateOptions {
  apiUrl: string;
  configPath: string;
  metadataPath: string;
  binaryPath: string;
  agentVersion: string;
  defaultUpdateIntervalMinutes: number;
  derivedKey: string;
  installNonce: string;
  logPrefix: string;
}

export function buildAgentBootstrapTemplate({
  apiUrl,
  configPath,
  metadataPath,
  binaryPath,
  agentVersion,
  defaultUpdateIntervalMinutes,
  derivedKey,
  installNonce,
  logPrefix
}: AgentBootstrapTemplateOptions): string {
  const escapedApiUrl = sanitizeLiteral(apiUrl);
  const escapedConfigPath = sanitizeLiteral(configPath);
  const escapedMetadataPath = sanitizeLiteral(metadataPath);
  const escapedBinaryPath = sanitizeLiteral(binaryPath);
  const escapedDerivedKey = sanitizeLiteral(derivedKey);
  const escapedInstallNonce = sanitizeLiteral(installNonce);
  const escapedLogPrefix = sanitizeLiteral(logPrefix || 'loadtest-agent');

  const script = `#!/usr/bin/env node
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');

const DEFAULT_CONFIG_PATH = process.env.LOADTEST_AGENT_CONFIG ?? '${escapedConfigPath}';
const DEFAULT_METADATA_PATH = process.env.LOADTEST_AGENT_METADATA ?? '${escapedMetadataPath}';
const DEFAULT_API_URL = '${escapedApiUrl}';
const AGENT_VERSION = '${agentVersion}';
const AGENT_FILE_PATH = process.env.LOADTEST_AGENT_BINARY_PATH ?? '${escapedBinaryPath}';
const DEFAULT_UPDATE_INTERVAL_MINUTES = ${defaultUpdateIntervalMinutes};
const FALLBACK_DERIVED_KEY_B64 = '${escapedDerivedKey}';
const INSTALL_NONCE = '${escapedInstallNonce}';
const LOG_PREFIX = '${escapedLogPrefix}';

let sessionEnvelope = null;

const CLI_ARGS = process.argv.slice(2);
if (CLI_ARGS.length > 0 && CLI_ARGS[0] === 'config') {
  handleConfigCommand(CLI_ARGS.slice(1));
  process.exit(0);
}

function ensureMetadata() {
  if (fs.existsSync(DEFAULT_METADATA_PATH)) {
    return;
  }

  const doc = {
    install_nonce: INSTALL_NONCE,
    derived_key: FALLBACK_DERIVED_KEY_B64,
    generated_at: new Date().toISOString(),
    script_version: AGENT_VERSION
  };

  fs.writeFileSync(DEFAULT_METADATA_PATH, JSON.stringify(doc, null, 2), { mode: 0o600 });
}

function loadMetadata() {
  ensureMetadata();

  try {
    const raw = fs.readFileSync(DEFAULT_METADATA_PATH, 'utf8');
    return JSON.parse(raw);
  } catch (error) {
    console.error('[\${LOG_PREFIX}] Failed to parse metadata:', error.message);
    throw error;
  }
}

function deriveKeyFromMetadata(metadata) {
  const keyB64 = metadata?.derived_key ?? FALLBACK_DERIVED_KEY_B64;
  return Buffer.from(keyB64, 'base64');
}

function encryptConfigDocument(metadata, configObj) {
  const derivedKey = deriveKeyFromMetadata(metadata);
  const dataKey = crypto.randomBytes(32);

  const wrap = (key, buffer) => {
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
  };

  return {
    version: 2,
    encryptedConfig: wrap(dataKey, Buffer.from(JSON.stringify(configObj), 'utf8')),
    wrappedKey: wrap(derivedKey, dataKey)
  };
}

function decryptConfigDocument(metadata, document) {
  if (!document || document.version !== 2 || !document.encryptedConfig || !document.wrappedKey) {
    throw new Error('Invalid encrypted config document.');
  }

  const derivedKey = deriveKeyFromMetadata(metadata);

  const unwrap = (key, blob) => {
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(blob.iv, 'base64'));
    decipher.setAuthTag(Buffer.from(blob.tag, 'base64'));
    return Buffer.concat([decipher.update(Buffer.from(blob.data, 'base64')), decipher.final()]);
  };

  const dataKey = unwrap(derivedKey, document.wrappedKey);
  const plaintext = unwrap(dataKey, document.encryptedConfig).toString('utf8');
  return JSON.parse(plaintext);
}

function parseLegacyConfig(content) {
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

function normalizeConfigShape(source) {
  const config = source || {};
  return {
    serverId: config.serverId || config.server_id || '',
    accessKey: config.accessKey || config.agent_access_key || '',
    secret: config.secret || config.agent_secret || '',
    apiUrl: config.apiUrl || config.api_url || DEFAULT_API_URL,
    pollIntervalSeconds: Number(config.pollIntervalSeconds || config.poll_interval_seconds || 30),
    telemetryIntervalMinutes: Number(
      config.telemetryIntervalMinutes || config.telemetry_interval_minutes || 60
    ),
    updateIntervalMinutes: Number(
      config.updateIntervalMinutes || config.update_interval_minutes || DEFAULT_UPDATE_INTERVAL_MINUTES
    ),
    logLevel: config.logLevel || config.log_level || 'info'
  };
}

function loadConfig() {
  ensureMetadata();

  if (!fs.existsSync(DEFAULT_CONFIG_PATH)) {
    return normalizeConfigShape({});
  }

  const raw = fs.readFileSync(DEFAULT_CONFIG_PATH, 'utf8');
  const trimmed = raw.trim();

  if (trimmed.startsWith('{')) {
    try {
      const parsed = JSON.parse(trimmed);
      if (parsed && parsed.version === 2) {
        const metadata = loadMetadata();
        return normalizeConfigShape(decryptConfigDocument(metadata, parsed));
      }
      return normalizeConfigShape(parsed);
    } catch {
      return normalizeConfigShape(parseLegacyConfig(raw));
    }
  }

  return normalizeConfigShape(parseLegacyConfig(raw));
}

function saveEncryptedConfig(configObj) {
  ensureMetadata();
  const metadata = loadMetadata();
  const document = encryptConfigDocument(metadata, configObj);
  fs.writeFileSync(DEFAULT_CONFIG_PATH, JSON.stringify(document, null, 2), { mode: 0o600 });
}

function parseCliArgs(argv) {
  const parsed = {};
  for (let i = 0; i < argv.length; i++) {
    const token = argv[i];
    if (!token.startsWith('--')) {
      continue;
    }
    const eqIndex = token.indexOf('=');
    if (eqIndex !== -1) {
      const key = token.slice(2, eqIndex);
      parsed[key] = token.slice(eqIndex + 1);
    } else {
      const key = token.slice(2);
      const next = argv[i + 1];
      if (next && !next.startsWith('--')) {
        parsed[key] = next;
        i++;
      } else {
        parsed[key] = 'true';
      }
    }
  }
  return parsed;
}

function handleConfigCommand(argv) {
  const args = parseCliArgs(argv);
  const required = ['server-id', 'access-key', 'secret', 'api-url'];

  for (const key of required) {
    if (!args[key]) {
      console.error(\`[\${LOG_PREFIX}] Missing --${'{'}key{'}'}=value\`);
      process.exit(1);
    }
  }

  const current = loadConfig();
  const nextConfig = {
    serverId: args['server-id'],
    accessKey: args['access-key'],
    secret: args.secret,
    apiUrl: args['api-url'],
    pollIntervalSeconds: Number(args['poll-interval'] || current.pollIntervalSeconds || 30),
    telemetryIntervalMinutes: Number(args['telemetry-interval'] || current.telemetryIntervalMinutes || 60),
    updateIntervalMinutes: Number(args['update-interval'] || current.updateIntervalMinutes || DEFAULT_UPDATE_INTERVAL_MINUTES),
    logLevel: args['log-level'] || current.logLevel || 'info'
  };

  saveEncryptedConfig(nextConfig);
  console.log('[\${LOG_PREFIX}] Configuration encrypted and updated.');
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function authenticate(config, apiBaseUrl) {
  const response = await fetch(\`\${apiBaseUrl}/agent/auth\`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      serverId: config.serverId,
      accessKey: config.accessKey,
      secret: config.secret,
      capabilities: ['envelope_v1']
    })
  });

  if (!response.ok) {
    throw new Error(\`Agent auth failed: \${response.status}\`);
  }

  const session = await response.json();
  if (session.envelope && session.envelope.version === 'v1' && session.envelope.key) {
    sessionEnvelope = {
      version: 'v1',
      key: Buffer.from(session.envelope.key, 'base64')
    };
  } else {
    sessionEnvelope = null;
  }

  return session;
}

async function fetchLatestAgent() {
  return null;
}

async function attemptSelfUpdate() {
  return false;
}

async function fetchNextScan(apiBaseUrl, token) {
  const headers = {
    Authorization: \`Bearer \${token}\`,
    'Content-Type': 'application/json'
  };

  let body = null;
  if (sessionEnvelope && sessionEnvelope.key) {
    headers['x-agent-envelope'] = 'v1';
    body = JSON.stringify(encryptEnvelopePayload(sessionEnvelope.key, {}));
  }

  const response = await fetch(\`\${apiBaseUrl}/agent/scans/next\`, {
    method: 'POST',
    headers,
    body
  });

  if (response.status === 204) {
    return null;
  }

  if (!response.ok) {
    throw new Error(\`Failed to fetch next scan: \${response.status}\`);
  }

  if (sessionEnvelope && sessionEnvelope.key && response.headers.get('x-agent-envelope') === 'v1') {
    const payload = await response.json();
    return decryptEnvelopePayload(sessionEnvelope.key, payload);
  }

  return response.json();
}

async function reportScanFailure(apiBaseUrl, token, scanId, reason) {
  const headers = {
    Authorization: \`Bearer \${token}\`,
    'Content-Type': 'application/json'
  };

  let payload = {
    status: 'FAILED',
    failureReason: reason,
    summary: {
      note: 'Reference agent installation script does not execute playbooks. Replace with production agent.'
    }
  };

  if (sessionEnvelope && sessionEnvelope.key) {
    headers['x-agent-envelope'] = 'v1';
    payload = encryptEnvelopePayload(sessionEnvelope.key, payload);
  }

  await fetch(\`\${apiBaseUrl}/agent/scans/\${scanId}/report\`, {
    method: 'POST',
    headers,
    body: JSON.stringify(payload)
  });
}

async function sendTelemetry(apiBaseUrl, token, config) {
  const headers = {
    Authorization: \`Bearer \${token}\`,
    'Content-Type': 'application/json'
  };

  const cpuPercent = calculateCpuPercent();
  const memoryPercent = calculateMemoryPercent();
  const diskPercent = calculateDiskPercent();

  let payload = {
    cpuPercent,
    memoryPercent,
    diskPercent,
    raw: {
      hostname: os.hostname(),
      platform: os.platform(),
      uptimeSeconds: Math.round(os.uptime()),
      loadAverage: os.loadavg(),
      freeMemBytes: os.freemem(),
      totalMemBytes: os.totalmem()
    }
  };

  if (sessionEnvelope && sessionEnvelope.key) {
    headers['x-agent-envelope'] = 'v1';
    payload = encryptEnvelopePayload(sessionEnvelope.key, payload);
  }

  await fetch(\`\${apiBaseUrl}/agent/telemetry\`, {
    method: 'POST',
    headers,
    body: JSON.stringify(payload)
  });
}


function calculateCpuPercent() {
  try {
    const start = os.cpus();
    const delayMs = 100;
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, delayMs);
    const end = os.cpus();

    let idleDiff = 0;
    let totalDiff = 0;

    for (let i = 0; i < end.length; i++) {
      const startTimes = start[i].times;
      const endTimes = end[i].times;
      const startTotal =
        startTimes.user + startTimes.nice + startTimes.sys + startTimes.idle + startTimes.irq;
      const endTotal =
        endTimes.user + endTimes.nice + endTimes.sys + endTimes.idle + endTimes.irq;

      idleDiff += endTimes.idle - startTimes.idle;
      totalDiff += endTotal - startTotal;
    }

    if (totalDiff === 0) {
      return null;
    }

    const usage = ((totalDiff - idleDiff) / totalDiff) * 100;
    return Number(usage.toFixed(2));
  } catch {
    return null;
  }
}

function calculateMemoryPercent() {
  try {
    const total = os.totalmem();
    const free = os.freemem();
    if (total === 0) {
      return null;
    }
    const used = total - free;
    return Number(((used / total) * 100).toFixed(2));
  } catch {
    return null;
  }
}

function calculateDiskPercent() {
  try {
    const stat = fs.statSync('/');
    if (!stat || !stat.blocks || !stat.blksize) {
      return null;
    }
    const total = stat.blocks * stat.blksize;
    const free = stat.blocks * stat.blksize;
    if (total === 0) {
      return null;
    }
    const used = total - free;
    return Number(((used / total) * 100).toFixed(2));
  } catch {
    return null;
  }
}

async function main() {
  const config = loadConfig();
  const pollIntervalMs = Math.max(5, Number(config.pollIntervalSeconds ?? 30)) * 1000;
  const telemetryIntervalMs = Math.max(1, Number(config.telemetryIntervalMinutes ?? 60)) * 60 * 1000;
  const updateIntervalMs =
    Math.max(10, Number(config.updateIntervalMinutes ?? DEFAULT_UPDATE_INTERVAL_MINUTES)) *
    60 *
    1000;
  const apiBaseUrl = (config.apiUrl ?? DEFAULT_API_URL).replace(/\\/$/, '');

  console.log('[\${LOG_PREFIX}] Starting agent loop');
  let sessionToken = null;
  let tokenExpiresAt = 0;
  let lastTelemetryAt = 0;
  let lastUpdateCheckAt = 0;

  while (true) {
    try {
      if (!sessionToken || Date.now() >= tokenExpiresAt - 60_000) {
        console.log('[\${LOG_PREFIX}] Authenticating with API');
        const session = await authenticate(config, apiBaseUrl);
        sessionToken = session.sessionToken;
        tokenExpiresAt = Date.now() + session.expiresInSeconds * 1000;
      }

      if (Date.now() - lastTelemetryAt >= telemetryIntervalMs) {
        await sendTelemetry(apiBaseUrl, sessionToken, config);
        lastTelemetryAt = Date.now();
        console.log('[\${LOG_PREFIX}] Telemetry sent');
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
        console.log(\`[\${LOG_PREFIX}] Received scan job \${job.id}, marking as failed placeholder\`);
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
      console.error('[\${LOG_PREFIX}] Error:', error.message);
      sessionToken = null;
      await sleep(Math.min(pollIntervalMs, 10_000));
    }
  }
}

main().catch((error) => {
  console.error('[\${LOG_PREFIX}] Fatal error:', error);
  process.exit(1);
});
`;

  return script
    .replace(`const LOG_PREFIX = '${escapedLogPrefix}';\n`, '')
    .replace(/\[\\\$\{LOG_PREFIX\}\]/g, `[${escapedLogPrefix}]`);
}
