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
Object.defineProperty(exports, "__esModule", { value: true });
exports.ServerAgentInstallController = void 0;
const common_1 = require("@nestjs/common");
const config_1 = require("@nestjs/config");
const public_decorator_1 = require("../../common/decorators/public.decorator");
let ServerAgentInstallController = class ServerAgentInstallController {
    constructor(configService) {
        this.configService = configService;
    }
    getInstallScript() {
        var _a, _b, _c, _d, _e, _f;
        const tarballUrl = (_a = this.configService.get('AGENT_INSTALL_TARBALL_URL')) !== null && _a !== void 0 ? _a : 'https://cdn.loadtest.dev/agents/loadtest-agent.tgz';
        const serviceName = (_b = this.configService.get('AGENT_SYSTEMD_SERVICE')) !== null && _b !== void 0 ? _b : 'loadtest-agent';
        const installDir = (_c = this.configService.get('AGENT_INSTALL_DIR')) !== null && _c !== void 0 ? _c : '/usr/local/lib/loadtest-agent';
        const binPath = (_d = this.configService.get('AGENT_BINARY_PATH')) !== null && _d !== void 0 ? _d : '/usr/local/bin/loadtest-agent';
        const configPath = (_e = this.configService.get('AGENT_CONFIG_PATH')) !== null && _e !== void 0 ? _e : '/etc/loadtest-agent/config.yaml';
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
api_url: "${(_f = this.configService.get('API_PUBLIC_URL')) !== null && _f !== void 0 ? _f : 'https://api.loadtest.dev'}"
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
};
exports.ServerAgentInstallController = ServerAgentInstallController;
__decorate([
    (0, public_decorator_1.Public)(),
    (0, common_1.Get)('agents/install.sh'),
    (0, common_1.Header)('Content-Type', 'text/x-shellscript'),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", []),
    __metadata("design:returntype", String)
], ServerAgentInstallController.prototype, "getInstallScript", null);
exports.ServerAgentInstallController = ServerAgentInstallController = __decorate([
    (0, common_1.Controller)(),
    __metadata("design:paramtypes", [config_1.ConfigService])
], ServerAgentInstallController);
//# sourceMappingURL=server-agent-install.controller.js.map