import {
  CallHandler,
  ExecutionContext,
  Injectable,
  NestInterceptor
} from '@nestjs/common';
import { createCipheriv, randomBytes } from 'node:crypto';
import type { Request, Response } from 'express';
import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';

type AgentAwareRequest = Request & {
  agentEnvelope?: {
    version: 'v1';
    key: Buffer;
  } | null;
};

interface AgentEncryptedPayload {
  ciphertext: string;
  iv: string;
  tag: string;
}

@Injectable()
export class AgentEnvelopeInterceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    const http = context.switchToHttp();
    const request = http.getRequest<AgentAwareRequest>();
    const response = http.getResponse<Response>();
    const envelope = request.agentEnvelope;

    if (!envelope || envelope.version !== 'v1') {
      return next.handle();
    }

    return next.handle().pipe(
      map((data: unknown) => {
        if (response.statusCode === 204 || data === undefined) {
          return data;
        }

        const payload = this.encrypt(envelope.key, data);
        response.setHeader('x-agent-envelope', 'v1');
        return payload;
      })
    );
  }

  private encrypt(key: Buffer, data: unknown): AgentEncryptedPayload {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    const ciphertext = Buffer.concat([
      cipher.update(Buffer.from(JSON.stringify(data), 'utf8')),
      cipher.final()
    ]);
    const tag = cipher.getAuthTag();

    return {
      ciphertext: ciphertext.toString('base64'),
      iv: iv.toString('base64'),
      tag: tag.toString('base64')
    };
  }
}
