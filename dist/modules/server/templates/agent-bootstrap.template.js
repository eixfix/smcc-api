"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.buildAgentBootstrapTemplate = buildAgentBootstrapTemplate;
const sanitizeLiteral = (value) => value.replace(/\\/g, "\\\\").replace(/`/g, "\\`");
function buildAgentBootstrapTemplate({ apiUrl, configPath, metadataPath, binaryPath, agentVersion, defaultUpdateIntervalMinutes, derivedKey, installNonce, logPrefix, configSignatureKey, updateSignatureKey, configRefreshIntervalMinutes }) {
    const escapedApiUrl = sanitizeLiteral(apiUrl);
    const escapedConfigPath = sanitizeLiteral(configPath);
    const escapedMetadataPath = sanitizeLiteral(metadataPath);
    const escapedBinaryPath = sanitizeLiteral(binaryPath);
    const escapedDerivedKey = sanitizeLiteral(derivedKey);
    const escapedInstallNonce = sanitizeLiteral(installNonce);
    const escapedLogPrefix = sanitizeLiteral(logPrefix || 'loadtest-agent');
    const escapedConfigSignatureKey = sanitizeLiteral(configSignatureKey);
    const escapedUpdateSignatureKey = sanitizeLiteral(updateSignatureKey);
    const refreshIntervalMinutes = Number.isFinite(configRefreshIntervalMinutes)
        ? configRefreshIntervalMinutes
        : 360;
    return `#!/usr/bin/env node
const crypto = require('node:crypto');
const fs = require('node:fs');
const { execSync } = require('node:child_process');
const os = require('node:os');

const DEFAULT_CONFIG_PATH = process.env.LOADTEST_AGENT_CONFIG ?? '${escapedConfigPath}';
const DEFAULT_METADATA_PATH = process.env.LOADTEST_AGENT_METADATA ?? '${escapedMetadataPath}';
const DEFAULT_API_URL = '${escapedApiUrl}';
const AGENT_VERSION = '${agentVersion}';
const AGENT_FILE_PATH = process.env.LOADTEST_AGENT_BINARY_PATH ?? '${escapedBinaryPath}';
const DEFAULT_UPDATE_INTERVAL_MINUTES = ${defaultUpdateIntervalMinutes};
const FALLBACK_DERIVED_KEY_B64 = '${escapedDerivedKey}';
const INSTALL_NONCE = '${escapedInstallNonce}';
const LOG_PREFIX = '[${escapedLogPrefix}]';
const CONFIG_SIGNATURE_KEY_B64 = '${escapedConfigSignatureKey}';
const UPDATE_SIGNATURE_KEY_B64 = '${escapedUpdateSignatureKey}';
const CONFIG_REFRESH_INTERVAL_MINUTES = Math.max(5, ${refreshIntervalMinutes});
const CONFIG_SIGNATURE_KEY = CONFIG_SIGNATURE_KEY_B64
  ? Buffer.from(CONFIG_SIGNATURE_KEY_B64, 'base64')
  : null;
const UPDATE_SIGNATURE_KEY = UPDATE_SIGNATURE_KEY_B64
  ? Buffer.from(UPDATE_SIGNATURE_KEY_B64, 'base64')
  : null;

let sessionEnvelope = null;
let configFailureCount = 0;
let updateFailureCount = 0;
let lastConfigSyncAt = 0;
let lastUpdateCheckAt = 0;

function logInfo(message) {
  console.log(LOG_PREFIX + ' ' + message);
}

function logError(message, error) {
  if (error !== undefined) {
    console.error(LOG_PREFIX + ' ' + message, error);
  } else {
    console.error(LOG_PREFIX + ' ' + message);
  }
}

const updateState = {
  status: 'idle',
  targetVersion: AGENT_VERSION,
  lastAttemptAt: null,
  lastError: null
};

const CLI_ARGS = process.argv.slice(2);
if (CLI_ARGS.length > 0 && CLI_ARGS[0] === 'config') {
  handleConfigCommand(CLI_ARGS.slice(1));
  process.exit(0);
}

function encryptEnvelopePayload(key, payload) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const plaintext = Buffer.from(JSON.stringify(payload ?? {}), 'utf8');
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();

  return {
    ciphertext: ciphertext.toString('base64'),
    iv: iv.toString('base64'),
    tag: tag.toString('base64')
  };
}

function decryptEnvelopePayload(key, payload) {
  if (
    !payload ||
    typeof payload.ciphertext !== 'string' ||
    typeof payload.iv !== 'string' ||
    typeof payload.tag !== 'string'
  ) {
    throw new Error('Malformed encrypted payload from API.');
  }

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(payload.iv, 'base64'));
  decipher.setAuthTag(Buffer.from(payload.tag, 'base64'));
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(payload.ciphertext, 'base64')),
    decipher.final()
  ]).toString('utf8');

  if (!plaintext) {
    return {};
  }

  return JSON.parse(plaintext);
}

function ensureSignatureKey(scope) {
  if (scope === 'config' && CONFIG_SIGNATURE_KEY) {
    return CONFIG_SIGNATURE_KEY;
  }
  if (scope === 'update' && UPDATE_SIGNATURE_KEY) {
    return UPDATE_SIGNATURE_KEY;
  }
  throw new Error('Missing ' + scope + ' signature key.');
}

function verifySignedDocument(scope, document) {
  if (!document || typeof document !== 'object') {
    throw new Error('Malformed ' + scope + ' document.');
  }

  const { signature, ...payload } = document;
  if (!signature || typeof signature !== 'string') {
    throw new Error('Missing ' + scope + ' signature from API.');
  }

  const key = ensureSignatureKey(scope);
  const serialized = JSON.stringify(payload ?? {});
  const expected = crypto.createHmac('sha256', key).update(serialized).digest();
  const provided = Buffer.from(signature, 'base64');

  if (expected.length !== provided.length || !crypto.timingSafeEqual(expected, provided)) {
    throw new Error(scope + ' signature verification failed.');
  }

  return payload;
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
    logError('Failed to parse metadata:', error.message);
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
      config.telemetryIntervalMinutes || config.telemetry_interval_minutes || 30
    ),
    updateIntervalMinutes: Number(
      config.updateIntervalMinutes || config.update_interval_minutes || DEFAULT_UPDATE_INTERVAL_MINUTES
    ),
    refreshIntervalMinutes: Number(
      config.refreshIntervalMinutes ||
        config.refresh_interval_minutes ||
        CONFIG_REFRESH_INTERVAL_MINUTES
    ),
    featureFlags:
      (config.featureFlags && typeof config.featureFlags === 'object' ? config.featureFlags : {}) ||
      {},
    configVersion: config.configVersion || 'bootstrap',
    logLevel: config.logLevel || config.log_level || 'info'
  };
}

function deriveIntervals(config) {
  return {
    pollIntervalMs: Math.max(5, Number(config.pollIntervalSeconds ?? 30)) * 1000,
    telemetryIntervalMs:
      Math.max(1, Number(config.telemetryIntervalMinutes ?? 30)) * 60 * 1000,
    updateIntervalMs:
      Math.max(10, Number(config.updateIntervalMinutes ?? DEFAULT_UPDATE_INTERVAL_MINUTES)) *
      60 *
      1000,
    configRefreshIntervalMs:
      Math.max(5, Number(config.refreshIntervalMinutes ?? CONFIG_REFRESH_INTERVAL_MINUTES)) *
      60 *
      1000
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
  const required = ['server-id', 'access-key', 'secret'];

  for (const key of required) {
    if (!args[key]) {
      logError('Missing --' + key + '=value');
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
    telemetryIntervalMinutes: Number(
      args['telemetry-interval'] || current.telemetryIntervalMinutes || 30
    ),
    updateIntervalMinutes:
      Number(args['update-interval'] || current.updateIntervalMinutes || DEFAULT_UPDATE_INTERVAL_MINUTES),
    refreshIntervalMinutes: Number(
      args['refresh-interval'] || current.refreshIntervalMinutes || CONFIG_REFRESH_INTERVAL_MINUTES
    ),
    featureFlags: current.featureFlags || {},
    configVersion: current.configVersion,
    logLevel: args['log-level'] || current.logLevel || 'info'
  };

  saveEncryptedConfig(nextConfig);
  logInfo('Configuration encrypted and updated.');
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function agentFetch(apiBaseUrl, path, token, options = {}) {
  const headers = {
    Authorization: 'Bearer ' + token
  };
  const hasEnvelope = sessionEnvelope && sessionEnvelope.key;

  if (hasEnvelope) {
    headers['x-agent-envelope'] = 'v1';
  }

  let body;
  if (options.body !== undefined) {
    headers['Content-Type'] = 'application/json';
    const payload = hasEnvelope
      ? encryptEnvelopePayload(sessionEnvelope.key, options.body)
      : options.body;
    body = JSON.stringify(payload);
  }

  const response = await fetch(apiBaseUrl + path, {
    method: options.method || (options.body !== undefined ? 'POST' : 'GET'),
    headers,
    body
  });

  if (response.status === 204) {
    return null;
  }

  if (!response.ok) {
    throw new Error('Request to ' + path + ' failed: ' + response.status);
  }

  if (hasEnvelope && response.headers.get('x-agent-envelope') === 'v1') {
    const encrypted = await response.json();
    return decryptEnvelopePayload(sessionEnvelope.key, encrypted);
  }

  const contentType = response.headers.get('content-type') ?? '';
  if (contentType.includes('application/json')) {
    return response.json();
  }

  return response.text();
}

async function fetchRemoteConfigDocument(apiBaseUrl, token) {
  const document = await agentFetch(apiBaseUrl, '/agent/config', token);
  if (!document) {
    return null;
  }
  return verifySignedDocument('config', document);
}

function mergeRemoteConfig(current, remote) {
  if (!remote || !remote.settings) {
    return current;
  }

  const settings = remote.settings;
  const next = {
    ...current,
    apiUrl: settings.apiUrl || current.apiUrl,
    pollIntervalSeconds:
      Number(settings.pollIntervalSeconds ?? current.pollIntervalSeconds) || current.pollIntervalSeconds,
    telemetryIntervalMinutes:
      Number(settings.telemetryIntervalMinutes ?? current.telemetryIntervalMinutes) ||
      current.telemetryIntervalMinutes,
    updateIntervalMinutes:
      Number(settings.updateIntervalMinutes ?? current.updateIntervalMinutes) ||
      current.updateIntervalMinutes,
    refreshIntervalMinutes:
      Number(settings.refreshIntervalMinutes ?? current.refreshIntervalMinutes) ||
      current.refreshIntervalMinutes,
    featureFlags:
      (settings.featureFlags && typeof settings.featureFlags === 'object'
        ? settings.featureFlags
        : current.featureFlags) ||
      {},
    configVersion: remote.version || current.configVersion
  };

  saveEncryptedConfig(next);
  logInfo('Applied remote config version ' + next.configVersion + '.');
  return next;
}

async function fetchUpdateManifestDocument(apiBaseUrl, token, currentVersion) {
  const suffix = currentVersion ? '?currentVersion=' + encodeURIComponent(currentVersion) : '';
  const document = await agentFetch(apiBaseUrl, '/agent/update' + suffix, token);
  if (!document) {
    return null;
  }
  return verifySignedDocument('update', document);
}

async function resolveUpdateArtifact(manifest) {
  if (manifest.inlineSource && manifest.inlineSource.encoding === 'base64') {
    return Buffer.from(manifest.inlineSource.data, 'base64');
  }

  if (manifest.downloadUrl) {
    const response = await fetch(manifest.downloadUrl);
    if (!response.ok) {
      throw new Error('Failed to download agent update: ' + response.status);
    }
    const arrayBuffer = await response.arrayBuffer();
    return Buffer.from(arrayBuffer);
  }

  throw new Error('Update manifest did not include a download URL or inline payload.');
}

function validateChecksum(manifest, buffer) {
  if (!manifest.checksum || manifest.checksum.algorithm !== 'sha256') {
    return;
  }
  const digest = crypto.createHash('sha256').update(buffer).digest('hex');
  if (digest !== manifest.checksum.value) {
    throw new Error('Downloaded agent artifact failed checksum validation.');
  }
}

function swapAgentBinary(buffer) {
  const tempPath = AGENT_FILE_PATH + '.tmp';
  fs.writeFileSync(tempPath, buffer, { mode: 0o755 });

  let backupPath = null;
  if (fs.existsSync(AGENT_FILE_PATH)) {
    backupPath = AGENT_FILE_PATH + '.bak';
    fs.copyFileSync(AGENT_FILE_PATH, backupPath);
  }

  fs.renameSync(tempPath, AGENT_FILE_PATH);
  return backupPath;
}

async function authenticate(config, apiBaseUrl) {
  const response = await fetch(apiBaseUrl + '/agent/auth', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      serverId: config.serverId,
      accessKey: config.accessKey,
      secret: config.secret,
      capabilities: ['envelope_v1', 'config_v1', 'update_v1']
    })
  });

  if (!response.ok) {
    throw new Error('Agent auth failed: ' + response.status);
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

async function attemptSelfUpdate(apiBaseUrl, token, config) {
  updateState.lastError = null;
  const manifest = await fetchUpdateManifestDocument(apiBaseUrl, token, config.configVersion || AGENT_VERSION);

  if (!manifest || manifest.version === AGENT_VERSION) {
    updateState.status = 'idle';
    updateState.targetVersion = AGENT_VERSION;
    return false;
  }

  updateState.targetVersion = manifest.version;
  updateState.status = 'downloading';
  updateState.lastAttemptAt = new Date().toISOString();

  let backupPath = null;
  try {
    const artifact = await resolveUpdateArtifact(manifest);
    validateChecksum(manifest, artifact);
    backupPath = swapAgentBinary(artifact);
    logInfo('Agent binary updated to ' + manifest.version + '.');
    updateState.status = 'applied';
    updateFailureCount = 0;
    return true;
  } catch (error) {
    updateFailureCount = Math.min(updateFailureCount + 1, 4);
    updateState.status = 'error';
    updateState.lastError = error.message;
    if (backupPath) {
      try {
        fs.copyFileSync(backupPath, AGENT_FILE_PATH);
      } catch {
        // no-op
      }
    }
    logError('Agent update failed:', error.message);
    return false;
  }
}

async function fetchNextScan(apiBaseUrl, token) {
  return agentFetch(apiBaseUrl, '/agent/scans/next', token, {
    method: 'POST',
    body: {}
  });
}

async function reportScanFailure(apiBaseUrl, token, scanId, reason) {
  await agentFetch(apiBaseUrl, '/agent/scans/' + scanId + '/report', token, {
    method: 'POST',
    body: {
      status: 'FAILED',
      failureReason: reason,
      summary: {
        note: 'Reference agent installation script does not execute playbooks. Replace with production agent.'
      }
    }
  });
}

async function sendTelemetry(apiBaseUrl, token, config) {
  const cpuPercent = calculateCpuPercent();
  const memoryPercent = calculateMemoryPercent();
  const diskPercent = calculateDiskPercent();
  const timestamp = new Date().toISOString();

  const payload = {
    cpuPercent,
    memoryPercent,
    diskPercent,
    agentVersion: AGENT_VERSION,
    configVersion: config.configVersion,
    updateStatus: updateState.status,
    lastUpdateCheckAt: lastUpdateCheckAt ? new Date(lastUpdateCheckAt).toISOString() : undefined,
    raw: {
      hostname: os.hostname(),
      platform: os.platform(),
      uptimeSeconds: Math.round(os.uptime()),
      loadAverage: os.loadavg(),
      freeMemBytes: os.freemem(),
      totalMemBytes: os.totalmem(),
      update: {
        status: updateState.status,
        targetVersion: updateState.targetVersion,
        lastAttemptAt: updateState.lastAttemptAt,
        lastError: updateState.lastError
      },
      config: {
        version: config.configVersion,
        refreshIntervalMinutes: config.refreshIntervalMinutes
      },
      timestamp
    }
  };

  await agentFetch(apiBaseUrl, '/agent/telemetry', token, {
    method: 'POST',
    body: payload
  });
}

function readProcStat() {
  const contents = fs.readFileSync('/proc/stat', 'utf8');
  const firstLine = contents.split(/\\n/)[0];
  const fields = firstLine.trim().split(/\\s+/);
  if (fields.length < 8 || fields[0] !== 'cpu') {
    throw new Error('Unexpected /proc/stat format');
  }
  const user = Number(fields[1]);
  const nice = Number(fields[2]);
  const sys = Number(fields[3]);
  const idle = Number(fields[4]);
  const iowait = Number(fields[5]);
  const irq = Number(fields[6]);
  const softirq = Number(fields[7]);
  const steal = Number(fields[8] ?? 0);
  return {
    idle: idle + iowait,
    total: user + nice + sys + idle + iowait + irq + softirq + steal
  };
}

function calculateCpuPercent() {
  try {
    const start = readProcStat();
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 500);
    const end = readProcStat();

    const idleDiff = end.idle - start.idle;
    const totalDiff = end.total - start.total;

    if (!Number.isFinite(totalDiff) || totalDiff <= 0) {
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
    if (typeof fs.statfsSync === 'function') {
      const stats = fs.statfsSync('/');
      if (
        stats &&
        Number.isFinite(stats.blocks) &&
        Number.isFinite(stats.bavail) &&
        Number.isFinite(stats.bsize)
      ) {
        const total = stats.blocks * stats.bsize;
        const free = stats.bavail * stats.bsize;
        if (Number.isFinite(total) && total > 0) {
          const used = total - free;
          return Number(((used / total) * 100).toFixed(2));
        }
      }
    }

    const output = execSync('df -P /', { encoding: 'utf8' });
    const lines = output.trim().split(/\\r?\\n/);
    if (lines.length < 2) {
      return null;
    }
    const parts = lines[1].trim().split(/\\s+/);
    if (parts.length < 5) {
      return null;
    }
    const totalBlocks = Number(parts[1]);
    const usedBlocks = Number(parts[2]);
    if (!Number.isFinite(totalBlocks) || totalBlocks === 0 || !Number.isFinite(usedBlocks)) {
      return null;
    }
    const usage = (usedBlocks / totalBlocks) * 100;
    return Number(usage.toFixed(2));
  } catch {
    return null;
  }
}

async function main() {
  let config = loadConfig();
  let intervals = deriveIntervals(config);
  let apiBaseUrl = (config.apiUrl ?? DEFAULT_API_URL).replace(/\/$/, '');

  logInfo('Starting agent loop');
  let sessionToken = null;
  let tokenExpiresAt = 0;
  let lastTelemetryAt = 0;

  while (true) {
    try {
      const now = Date.now();

      if (!sessionToken || now >= tokenExpiresAt - 60_000) {
        logInfo('Telemetry sent');
        const session = await authenticate(config, apiBaseUrl);
        sessionToken = session.sessionToken;
        tokenExpiresAt = Date.now() + session.expiresInSeconds * 1000;
      }

      const configBackoff = Math.max(1, configFailureCount > 0 ? 2 ** configFailureCount : 1);
      if (now - lastConfigSyncAt >= intervals.configRefreshIntervalMs * configBackoff) {
        try {
          const remote = await fetchRemoteConfigDocument(apiBaseUrl, sessionToken);
          lastConfigSyncAt = Date.now();
          configFailureCount = 0;
          if (remote && remote.version && remote.version !== config.configVersion) {
            config = mergeRemoteConfig(config, remote);
            intervals = deriveIntervals(config);
            apiBaseUrl = (config.apiUrl ?? DEFAULT_API_URL).replace(/\/$/, '');
          }
        } catch (error) {
          configFailureCount = Math.min(configFailureCount + 1, 4);
          lastConfigSyncAt = Date.now();
          logError('Remote config refresh failed:', error.message);
        }
      }

      if (now - lastTelemetryAt >= intervals.telemetryIntervalMs) {
        await sendTelemetry(apiBaseUrl, sessionToken, config);
        lastTelemetryAt = now;
        logInfo('Telemetry sent');
      }

      const updateBackoff = Math.max(1, updateFailureCount > 0 ? 2 ** updateFailureCount : 1);
      if (now - lastUpdateCheckAt >= intervals.updateIntervalMs * updateBackoff) {
        lastUpdateCheckAt = now;
        const updated = await attemptSelfUpdate(apiBaseUrl, sessionToken, config);
        if (updated) {
          await sleep(2000);
          process.exit(0);
        }
      }

      const job = await fetchNextScan(apiBaseUrl, sessionToken);

      if (job) {
        logInfo('Received scan job ' + job.id + ', marking as failed placeholder');
        await reportScanFailure(
          apiBaseUrl,
          sessionToken,
          job.id,
          'Reference agent does not execute playbooks.'
        );
      } else {
        await sleep(intervals.pollIntervalMs);
      }
    } catch (error) {
      logError('Error:', error.message);
      sessionToken = null;
      await sleep(Math.min(intervals.pollIntervalMs, 10_000));
    }
  }
}

main().catch((error) => {
  logError('Fatal error:', error);
  process.exit(1);
});
`;
}
//# sourceMappingURL=agent-bootstrap.template.js.map