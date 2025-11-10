import { Controller, Get, Header } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

import { Public } from '../../common/decorators/public.decorator';

@Controller()
export class ServerAgentInstallController {
  constructor(private readonly configService: ConfigService) {}

  @Public()
  @Get('agents/install.sh')
  @Header('Content-Type', 'text/x-shellscript')
  getInstallScript(): string {
    const tarballUrl =
      this.configService.get<string>('AGENT_INSTALL_TARBALL_URL') ??
      'https://cdn.loadtest.dev/agents/loadtest-agent.tgz';
    const serviceName =
      this.configService.get<string>('AGENT_SYSTEMD_SERVICE') ?? 'loadtest-agent';
    const installDir =
      this.configService.get<string>('AGENT_INSTALL_DIR') ?? '/usr/local/lib/loadtest-agent';
    const binPath =
      this.configService.get<string>('AGENT_BINARY_PATH') ?? '/usr/local/bin/loadtest-agent';
    const configPath =
      this.configService.get<string>('AGENT_CONFIG_PATH') ?? '/etc/loadtest-agent/config.yaml';

    const serviceUnitPath = `/etc/systemd/system/${serviceName}.service`;
    const installDirEscaped = installDir.replace(/"/g, '\\"');
    const binPathEscaped = binPath.replace(/"/g, '\\"');
    const configPathEscaped = configPath.replace(/"/g, '\\"');

    return `#!/usr/bin/env bash
set -euo pipefail

echo "[loadtest] Installing agent files..."
INSTALL_DIR="${installDirEscaped}"
BIN_PATH="${binPathEscaped}"
CONFIG_PATH="${configPathEscaped}"
SERVICE_NAME="${serviceName}"
SERVICE_PATH="${serviceUnitPath}"
TARBALL_URL="${tarballUrl}"

mkdir -p "$INSTALL_DIR"
curl -fsSL "$TARBALL_URL" | tar xz -C "$INSTALL_DIR"

install -m 755 "$INSTALL_DIR/loadtest-agent" "$BIN_PATH"
install -d -m 755 "$(dirname "$CONFIG_PATH")"
if [ ! -f "$CONFIG_PATH" ]; then
  cat <<'EOF' > "$CONFIG_PATH"
server_id: "<server-id>"
agent_access_key: "<access-key>"
agent_secret: "<secret>"
api_url: "${this.configService.get<string>('API_PUBLIC_URL') ?? 'https://api.loadtest.dev'}"
poll_interval_seconds: 30
telemetry_interval_minutes: 60
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
ExecStart=${binPathEscaped} --config ${configPathEscaped}
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
}
