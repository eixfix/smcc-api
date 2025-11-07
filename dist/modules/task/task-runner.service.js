"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var TaskRunnerService_1;
Object.defineProperty(exports, "__esModule", { value: true });
exports.TaskRunnerService = void 0;
const common_1 = require("@nestjs/common");
const node_child_process_1 = require("node:child_process");
const node_crypto_1 = require("node:crypto");
const promises_1 = require("node:fs/promises");
const node_os_1 = require("node:os");
const node_path_1 = require("node:path");
let TaskRunnerService = TaskRunnerService_1 = class TaskRunnerService {
    constructor() {
        this.logger = new common_1.Logger(TaskRunnerService_1.name);
        this.queue = [];
        this.running = false;
        this.bundleReady = false;
        this.loadTestsRoot = (0, node_path_1.resolve)(process.cwd(), '../load-tests');
        this.scriptByMode = {
            SMOKE: 'dist/smoke/bootstrap.js',
            STRESS: 'dist/smoke/bootstrap.js',
            SOAK: 'dist/smoke/bootstrap.js',
            SPIKE: 'dist/smoke/bootstrap.js',
            CUSTOM: 'dist/smoke/bootstrap.js'
        };
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
        const code = await this.execCommand('npm', ['run', 'build'], this.loadTestsRoot);
        if (code !== 0) {
            throw new Error('Failed to compile k6 bundles. Ensure dependencies are installed.');
        }
    }
    async execute(request) {
        var _a, _b, _c;
        const scriptPath = (_a = this.scriptByMode[request.mode]) !== null && _a !== void 0 ? _a : this.scriptByMode.SMOKE;
        const resolvedScript = (0, node_path_1.resolve)(this.loadTestsRoot, scriptPath);
        const summaryDir = await (0, promises_1.mkdtemp)((0, node_path_1.join)((0, node_os_1.tmpdir)(), 'k6-summary-'));
        const summaryFile = (0, node_path_1.join)(summaryDir, `${(0, node_crypto_1.randomUUID)()}.json`);
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
        const exitCode = await this.execCommand('k6', args, this.loadTestsRoot, env);
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
        const executable = process.platform === 'win32' && !command.endsWith('.cmd')
            ? `${command}.cmd`
            : command;
        return new Promise((resolve, reject) => {
            const child = (0, node_child_process_1.spawn)(executable, args, {
                cwd,
                env,
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
    toSummary(rawJson, request) {
        var _a, _b, _c, _d, _e, _f, _g, _h, _j, _k, _l, _m, _o, _p, _q;
        try {
            const parsed = JSON.parse(rawJson);
            const httpDuration = (_b = (_a = parsed.metrics) === null || _a === void 0 ? void 0 : _a.http_req_duration) !== null && _b !== void 0 ? _b : {};
            const httpReqFailed = (_d = (_c = parsed.metrics) === null || _c === void 0 ? void 0 : _c.http_req_failed) !== null && _d !== void 0 ? _d : {};
            const httpReqs = (_f = (_e = parsed.metrics) === null || _e === void 0 ? void 0 : _e.http_reqs) !== null && _f !== void 0 ? _f : {};
            const iterations = (_h = (_g = parsed.metrics) === null || _g === void 0 ? void 0 : _g.iterations) !== null && _h !== void 0 ? _h : {};
            const totalRequests = (_k = (_j = httpReqs.count) !== null && _j !== void 0 ? _j : iterations.count) !== null && _k !== void 0 ? _k : 0;
            const failureRate = (_l = httpReqFailed.rate) !== null && _l !== void 0 ? _l : 0;
            const successRate = Number(((1 - failureRate) * 100).toFixed(2));
            return {
                scenario: {
                    mode: request.mode,
                    totalRequests
                },
                metrics: {
                    averageMs: (_m = httpDuration.avg) !== null && _m !== void 0 ? _m : null,
                    minMs: (_o = httpDuration.min) !== null && _o !== void 0 ? _o : null,
                    maxMs: (_p = httpDuration.max) !== null && _p !== void 0 ? _p : null,
                    p95Ms: (_q = httpDuration['p(95)']) !== null && _q !== void 0 ? _q : null,
                    successRate
                },
                results: {
                    totalRequests,
                    successCount: Math.max(0, Math.round(totalRequests * (1 - failureRate))),
                    failureCount: Math.max(0, Math.round(totalRequests * failureRate))
                },
                raw: {
                    http_req_duration: httpDuration,
                    http_req_failed: httpReqFailed,
                    http_reqs: httpReqs,
                    iterations
                }
            };
        }
        catch (error) {
            this.logger.warn(`Unable to parse k6 summary JSON: ${error.message}`);
            return null;
        }
    }
};
exports.TaskRunnerService = TaskRunnerService;
exports.TaskRunnerService = TaskRunnerService = TaskRunnerService_1 = __decorate([
    (0, common_1.Injectable)()
], TaskRunnerService);
//# sourceMappingURL=task-runner.service.js.map