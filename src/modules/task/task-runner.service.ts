import { Injectable, Logger } from '@nestjs/common';
import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import * as path from 'node:path';

type RunRequest = {
  taskId: string;
  targetUrl: string;
  mode: string;
  method: string;
  headers?: Record<string, string>;
  payload?: string;
  customVus?: number;
  durationSeconds?: number;
};

export type TaskRunSummary = {
  status: 'completed' | 'failed';
  startedAt: Date;
  completedAt: Date;
  summary: Record<string, unknown> | null;
};

type QueueJob = {
  request: RunRequest;
  resolve: (summary: TaskRunSummary) => void;
  reject: (error: unknown) => void;
};

@Injectable()
export class TaskRunnerService {
  private readonly logger = new Logger(TaskRunnerService.name);
  private readonly queue: QueueJob[] = [];
  private running = false;
  private bundleReady = false;
  private readonly loadTestsRoot: string;
  private readonly npmPath: string;
  private readonly k6Path: string | null;
  private readonly scriptByMode: Record<string, string> = {
    SMOKE: 'dist/smoke/bootstrap.js',
    STRESS: 'dist/smoke/bootstrap.js',
    SOAK: 'dist/smoke/bootstrap.js',
    SPIKE: 'dist/smoke/bootstrap.js',
    CUSTOM: 'dist/smoke/bootstrap.js'
  };

  constructor() {
    const serverDefaultRoot = path.resolve(process.cwd(), '../load-test/current');
    const localDefaultRoot = path.resolve(process.cwd(), '../load-tests');
    const defaultRoot = existsSync(serverDefaultRoot) ? serverDefaultRoot : localDefaultRoot;

    this.loadTestsRoot = process.env.LOAD_TESTS_ROOT
      ? path.resolve(process.env.LOAD_TESTS_ROOT)
      : defaultRoot;
    this.logger.log(`Using LOAD_TESTS_ROOT: ${this.loadTestsRoot}`);

    this.npmPath = this.normalizeExecutable(process.env.NPM_PATH) ?? 'npm';
    this.k6Path = this.normalizeExecutable(process.env.K6_PATH);

    this.logger.log(`Using npm executable: ${this.npmPath}`);
    if (this.k6Path) {
      this.logger.log(`Using k6 executable: ${this.k6Path}`);
    } else {
      this.logger.log('k6 executable not set; falling back to npm exec k6');
    }
  }

  async enqueue(request: RunRequest): Promise<TaskRunSummary> {
    return new Promise((resolve, reject) => {
      this.queue.push({ request, resolve, reject });
      void this.processQueue();
    });
  }

  private async processQueue(): Promise<void> {
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
      } catch (error) {
        this.logger.error('Task run failed', error as Error);
        job.reject(error);
      }
    }

    this.running = false;
  }

  private async buildBundles(): Promise<void> {
    this.logger.log('Compiling k6 bundles for load-tests');
    const code = await this.execCommand(this.npmPath, ['run', 'build'], this.loadTestsRoot);
    if (code !== 0) {
      throw new Error('Failed to compile k6 bundles. Ensure dependencies are installed.');
    }
  }

  private async execute(request: RunRequest): Promise<TaskRunSummary> {
    const scriptPath =
      this.scriptByMode[request.mode] ?? this.scriptByMode.SMOKE;

    const resolvedScript = path.resolve(this.loadTestsRoot, scriptPath);
    const summaryDir = await mkdtemp(path.join(tmpdir(), 'k6-summary-'));
    const summaryFile = path.join(summaryDir, `${randomUUID()}.json`);

    const env: NodeJS.ProcessEnv = {
      ...process.env,
      TARGET_URL: request.targetUrl,
      MODE: request.mode,
      API_BASE_URL: request.targetUrl,
      K6_NO_USAGE_REPORT: 'true',
      HTTP_METHOD: request.method,
      HTTP_HEADERS: request.headers ? JSON.stringify(request.headers) : '',
      HTTP_BODY: request.payload ?? ''
    };

    if (typeof request.customVus === 'number' && Number.isFinite(request.customVus)) {
      env.CUSTOM_VUS = String(request.customVus);
    }

    if (typeof request.durationSeconds === 'number' && Number.isFinite(request.durationSeconds)) {
      env.CUSTOM_DURATION_SECONDS = String(request.durationSeconds);
    }

    const args = ['run', resolvedScript, '--summary-export', summaryFile];
    this.logger.log(
      `Executing k6 scenario for task ${request.taskId} (${request.mode})`
    );

    const startedAt = new Date();
    const exitCode = this.k6Path
      ? await this.execCommand(this.k6Path, args, this.loadTestsRoot, env)
      : await this.execCommand(this.npmPath, ['exec', '--yes', 'k6', ...args], this.loadTestsRoot, env);
    const completedAt = new Date();
    const status: 'completed' | 'failed' = exitCode === 0 ? 'completed' : 'failed';

    let summary: Record<string, unknown> | null = null;

    if (status === 'completed') {
      try {
        const raw = await readFile(summaryFile, 'utf-8');
        summary = this.toSummary(raw, request);
      } catch (error) {
        this.logger.warn(
          `Failed to read k6 summary for task ${request.taskId}: ${(error as Error).message}`
        );
      }
    }

    await rm(summaryDir, { recursive: true, force: true }).catch(() => undefined);

    if (!summary) {
      summary = {};
    }

    summary.request = {
      method: request.method,
      headers: request.headers ?? {},
      hasPayload: Boolean(request.payload)
    };

    return { status, startedAt, completedAt, summary };
  }

  private async execCommand(
    command: string,
    args: string[],
    cwd: string,
    env?: NodeJS.ProcessEnv
  ): Promise<number> {
    const needsCmdExtension =
      process.platform === 'win32' &&
      !command.endsWith('.cmd') &&
      !command.includes(path.sep);
    const executable = needsCmdExtension ? `${command}.cmd` : command;

    return new Promise((resolve, reject) => {
      const child = spawn(executable, args, {
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

  private normalizeExecutable(value?: string): string | null {
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

  private toSummary(
    rawJson: string,
    request: RunRequest
  ): Record<string, unknown> | null {
    try {
      const parsed = JSON.parse(rawJson) as unknown;
      const metrics = this.toMetricsRecord(parsed);
      if (!metrics) {
        return null;
      }

      const httpDuration = this.toMetricSnapshot(metrics['http_req_duration']);
      const httpReqFailed = this.toMetricSnapshot(metrics['http_req_failed']);
      const httpReqs = this.toMetricSnapshot(metrics['http_reqs']);
      const iterations = this.toMetricSnapshot(metrics['iterations']);

      const totalRequests = httpReqs.count ?? iterations.count ?? 0;
      const failureRate = httpReqFailed.rate ?? 0;
      const successRate = Number(((1 - failureRate) * 100).toFixed(2));

      return {
        scenario: {
          mode: request.mode,
          totalRequests
        },
        metrics: {
          averageMs: httpDuration.avg ?? null,
          minMs: httpDuration.min ?? null,
          maxMs: httpDuration.max ?? null,
          p95Ms: httpDuration.p95 ?? null,
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
    } catch (error) {
      this.logger.warn(`Unable to parse k6 summary JSON: ${(error as Error).message}`);
      return null;
    }
  }

  private toMetricsRecord(value: unknown): Record<string, unknown> | null {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      return null;
    }
    const record = value as Record<string, unknown>;
    const metrics = record.metrics;
    if (!metrics || typeof metrics !== 'object' || Array.isArray(metrics)) {
      return null;
    }
    return metrics as Record<string, unknown>;
  }

  private toMetricSnapshot(value: unknown): {
    avg: number | null;
    min: number | null;
    max: number | null;
    p95: number | null;
    count: number | null;
    rate: number | null;
  } {
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

    const metric = value as Record<string, unknown>;
    return {
      avg: this.toFiniteNumber(metric.avg),
      min: this.toFiniteNumber(metric.min),
      max: this.toFiniteNumber(metric.max),
      p95: this.toFiniteNumber(metric['p(95)']),
      count: this.toFiniteNumber(metric.count),
      rate: this.toFiniteNumber(metric.rate)
    };
  }

  private toFiniteNumber(value: unknown): number | null {
    return typeof value === 'number' && Number.isFinite(value) ? value : null;
  }
}
