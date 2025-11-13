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
var TaskRunnerService_1;
Object.defineProperty(exports, "__esModule", { value: true });
exports.TaskRunnerService = void 0;
const common_1 = require("@nestjs/common");
const node_child_process_1 = require("node:child_process");
const node_crypto_1 = require("node:crypto");
const node_fs_1 = require("node:fs");
const promises_1 = require("node:fs/promises");
const node_os_1 = require("node:os");
const path = require("node:path");
let TaskRunnerService = TaskRunnerService_1 = class TaskRunnerService {
    constructor() {
        var _a;
        this.logger = new common_1.Logger(TaskRunnerService_1.name);
        this.queue = [];
        this.running = false;
        this.bundleReady = false;
        this.scriptByMode = {
            SMOKE: 'dist/smoke/bootstrap.js',
            STRESS: 'dist/smoke/bootstrap.js',
            SOAK: 'dist/smoke/bootstrap.js',
            SPIKE: 'dist/smoke/bootstrap.js',
            CUSTOM: 'dist/smoke/bootstrap.js'
        };
        const serverDefaultRoot = path.resolve(process.cwd(), '../load-test/current');
        const localDefaultRoot = path.resolve(process.cwd(), '../load-tests');
        const defaultRoot = (0, node_fs_1.existsSync)(serverDefaultRoot) ? serverDefaultRoot : localDefaultRoot;
        this.loadTestsRoot = process.env.LOAD_TESTS_ROOT
            ? path.resolve(process.env.LOAD_TESTS_ROOT)
            : defaultRoot;
        this.logger.log(`Using LOAD_TESTS_ROOT: ${this.loadTestsRoot}`);
        this.npmPath = (_a = this.normalizeExecutable(process.env.NPM_PATH)) !== null && _a !== void 0 ? _a : 'npm';
        this.k6Path = this.normalizeExecutable(process.env.K6_PATH);
        this.logger.log(`Using npm executable: ${this.npmPath}`);
        if (this.k6Path) {
            this.logger.log(`Using k6 executable: ${this.k6Path}`);
        }
        else {
            this.logger.log('k6 executable not set; falling back to npm exec k6');
        }
    }
    async enqueue(request) {
        return new Promise((resolve, reject) => {
            this.queue.push({ request, resolve, reject });
            void this.processQueue();
        });
    }
    async processQueue() {
        if (this.running) {
            return;
        }
        this.running = true;
        while (this.queue.length > 0) {
            const job = this.queue.shift();
            if (!job) {
                continue;
            }
            try {
                if (!this.bundleReady) {
                    await this.buildBundles();
                    this.bundleReady = true;
                }
                const summary = await this.execute(job.request);
                job.resolve(summary);
            }
            catch (error) {
                this.logger.error('Task run failed', error);
                job.reject(error);
            }
        }
        this.running = false;
    }
    async buildBundles() {
        this.logger.log('Compiling k6 bundles for load-tests');
        const code = await this.execCommand(this.npmPath, ['run', 'build'], this.loadTestsRoot);
        if (code !== 0) {
            throw new Error('Failed to compile k6 bundles. Ensure dependencies are installed.');
        }
    }
    async execute(request) {
        var _a, _b, _c;
        const scriptPath = (_a = this.scriptByMode[request.mode]) !== null && _a !== void 0 ? _a : this.scriptByMode.SMOKE;
        const resolvedScript = path.resolve(this.loadTestsRoot, scriptPath);
        const summaryDir = await (0, promises_1.mkdtemp)(path.join((0, node_os_1.tmpdir)(), 'k6-summary-'));
        const summaryFile = path.join(summaryDir, `${(0, node_crypto_1.randomUUID)()}.json`);
        const env = {
            ...process.env,
            TARGET_URL: request.targetUrl,
            MODE: request.mode,
            API_BASE_URL: request.targetUrl,
            K6_NO_USAGE_REPORT: 'true',
            HTTP_METHOD: request.method,
            HTTP_HEADERS: request.headers ? JSON.stringify(request.headers) : '',
            HTTP_BODY: (_b = request.payload) !== null && _b !== void 0 ? _b : ''
        };
        if (typeof request.customVus === 'number' && Number.isFinite(request.customVus)) {
            env.CUSTOM_VUS = String(request.customVus);
        }
        if (typeof request.durationSeconds === 'number' && Number.isFinite(request.durationSeconds)) {
            env.CUSTOM_DURATION_SECONDS = String(request.durationSeconds);
        }
        const args = ['run', resolvedScript, '--summary-export', summaryFile];
        this.logger.log(`Executing k6 scenario for task ${request.taskId} (${request.mode})`);
        const startedAt = new Date();
        const exitCode = this.k6Path
            ? await this.execCommand(this.k6Path, args, this.loadTestsRoot, env)
            : await this.execCommand(this.npmPath, ['exec', '--yes', 'k6', ...args], this.loadTestsRoot, env);
        const completedAt = new Date();
        const status = exitCode === 0 ? 'completed' : 'failed';
        let summary = null;
        if (status === 'completed') {
            try {
                const raw = await (0, promises_1.readFile)(summaryFile, 'utf-8');
                summary = this.toSummary(raw, request);
            }
            catch (error) {
                this.logger.warn(`Failed to read k6 summary for task ${request.taskId}: ${error.message}`);
            }
        }
        await (0, promises_1.rm)(summaryDir, { recursive: true, force: true }).catch(() => undefined);
        if (!summary) {
            summary = {};
        }
        summary.request = {
            method: request.method,
            headers: (_c = request.headers) !== null && _c !== void 0 ? _c : {},
            hasPayload: Boolean(request.payload)
        };
        return { status, startedAt, completedAt, summary };
    }
    async execCommand(command, args, cwd, env) {
        const needsCmdExtension = process.platform === 'win32' &&
            !command.endsWith('.cmd') &&
            !command.includes(path.sep);
        const executable = needsCmdExtension ? `${command}.cmd` : command;
        return new Promise((resolve, reject) => {
            const child = (0, node_child_process_1.spawn)(executable, args, {
                cwd,
                env: { ...process.env, ...env },
                stdio: 'inherit'
            });
            child.on('error', (error) => reject(error));
            child.on('close', (code) => {
                if (code === null) {
                    reject(new Error(`${command} exited abnormally.`));
                    return;
                }
                resolve(code);
            });
        });
    }
    normalizeExecutable(value) {
        if (!value) {
            return null;
        }
        const trimmed = value.trim();
        if (!trimmed) {
            return null;
        }
        if (path.isAbsolute(trimmed)) {
            return trimmed;
        }
        if (trimmed.startsWith('./') || trimmed.startsWith('../')) {
            return path.resolve(process.cwd(), trimmed);
        }
        return trimmed;
    }
    toSummary(rawJson, request) {
        var _a, _b, _c, _d, _e, _f, _g;
        try {
            const parsed = JSON.parse(rawJson);
            const metrics = this.toMetricsRecord(parsed);
            if (!metrics) {
                return null;
            }
            const httpDuration = this.toMetricSnapshot(metrics['http_req_duration']);
            const httpReqFailed = this.toMetricSnapshot(metrics['http_req_failed']);
            const httpReqs = this.toMetricSnapshot(metrics['http_reqs']);
            const iterations = this.toMetricSnapshot(metrics['iterations']);
            const totalRequests = (_b = (_a = httpReqs.count) !== null && _a !== void 0 ? _a : iterations.count) !== null && _b !== void 0 ? _b : 0;
            const failureRate = (_c = httpReqFailed.rate) !== null && _c !== void 0 ? _c : 0;
            const successRate = Number(((1 - failureRate) * 100).toFixed(2));
            return {
                scenario: {
                    mode: request.mode,
                    totalRequests
                },
                metrics: {
                    averageMs: (_d = httpDuration.avg) !== null && _d !== void 0 ? _d : null,
                    minMs: (_e = httpDuration.min) !== null && _e !== void 0 ? _e : null,
                    maxMs: (_f = httpDuration.max) !== null && _f !== void 0 ? _f : null,
                    p95Ms: (_g = httpDuration.p95) !== null && _g !== void 0 ? _g : null,
                    successRate
                },
                results: {
                    totalRequests,
                    successCount: Math.max(0, Math.round(totalRequests * (1 - failureRate))),
                    failureCount: Math.max(0, Math.round(totalRequests * failureRate))
                },
                raw: {
                    http_req_duration: metrics['http_req_duration'],
                    http_req_failed: metrics['http_req_failed'],
                    http_reqs: metrics['http_reqs'],
                    iterations: metrics['iterations']
                }
            };
        }
        catch (error) {
            this.logger.warn(`Unable to parse k6 summary JSON: ${error.message}`);
            return null;
        }
    }
    toMetricsRecord(value) {
        if (!value || typeof value !== 'object' || Array.isArray(value)) {
            return null;
        }
        const record = value;
        const metrics = record.metrics;
        if (!metrics || typeof metrics !== 'object' || Array.isArray(metrics)) {
            return null;
        }
        return metrics;
    }
    toMetricSnapshot(value) {
        if (!value || typeof value !== 'object' || Array.isArray(value)) {
            return {
                avg: null,
                min: null,
                max: null,
                p95: null,
                count: null,
                rate: null
            };
        }
        const metric = value;
        return {
            avg: this.toFiniteNumber(metric.avg),
            min: this.toFiniteNumber(metric.min),
            max: this.toFiniteNumber(metric.max),
            p95: this.toFiniteNumber(metric['p(95)']),
            count: this.toFiniteNumber(metric.count),
            rate: this.toFiniteNumber(metric.rate)
        };
    }
    toFiniteNumber(value) {
        return typeof value === 'number' && Number.isFinite(value) ? value : null;
    }
};
exports.TaskRunnerService = TaskRunnerService;
exports.TaskRunnerService = TaskRunnerService = TaskRunnerService_1 = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [])
], TaskRunnerService);
//# sourceMappingURL=task-runner.service.js.map