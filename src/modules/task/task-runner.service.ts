import { Injectable, Logger } from '@nestjs/common';
import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

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
  private readonly loadTestsRoot = resolve(process.cwd(), '../load-tests');
  private readonly scriptByMode: Record<string, string> = {
    SMOKE: 'dist/smoke/bootstrap.js',
    STRESS: 'dist/smoke/bootstrap.js',
    SOAK: 'dist/smoke/bootstrap.js',
    SPIKE: 'dist/smoke/bootstrap.js',
    CUSTOM: 'dist/smoke/bootstrap.js'
  };

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
    const code = await this.execCommand('npm', ['run', 'build'], this.loadTestsRoot);
    if (code !== 0) {
      throw new Error('Failed to compile k6 bundles. Ensure dependencies are installed.');
    }
  }

  private async execute(request: RunRequest): Promise<TaskRunSummary> {
    const scriptPath =
      this.scriptByMode[request.mode] ?? this.scriptByMode.SMOKE;

    const resolvedScript = resolve(this.loadTestsRoot, scriptPath);
    const summaryDir = await mkdtemp(join(tmpdir(), 'k6-summary-'));
    const summaryFile = join(summaryDir, `${randomUUID()}.json`);

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
    const exitCode = await this.execCommand('k6', args, this.loadTestsRoot, env);
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
    const executable = process.platform === 'win32' && !command.endsWith('.cmd')
      ? `${command}.cmd`
      : command;

    return new Promise((resolve, reject) => {
      const child = spawn(executable, args, {
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

  private toSummary(
    rawJson: string,
    request: RunRequest
  ): Record<string, unknown> | null {
    try {
      const parsed = JSON.parse(rawJson) as {
        metrics?: Record<string, any>;
      };

      const httpDuration = parsed.metrics?.http_req_duration ?? {};
      const httpReqFailed = parsed.metrics?.http_req_failed ?? {};
      const httpReqs = parsed.metrics?.http_reqs ?? {};
      const iterations = parsed.metrics?.iterations ?? {};

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
          p95Ms: httpDuration['p(95)'] ?? null,
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
    } catch (error) {
      this.logger.warn(`Unable to parse k6 summary JSON: ${(error as Error).message}`);
      return null;
    }
  }
}
