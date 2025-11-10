import type { Request } from 'express';

export function normalizeIp(ip?: string | null): string | null {
  if (!ip) {
    return null;
  }

  let trimmed = ip.trim();
  if (trimmed.length === 0) {
    return null;
  }

  if (trimmed.startsWith('::ffff:')) {
    trimmed = trimmed.slice(7);
  }

  return trimmed.toLowerCase();
}

export function extractClientIp(request: Request): string | null {
  const forwarded = request.headers['x-forwarded-for'];
  if (typeof forwarded === 'string' && forwarded.length > 0) {
    const [first] = forwarded.split(',');
    const normalized = normalizeIp(first);
    if (normalized) {
      return normalized;
    }
  }

  const ip = request.ip ?? request.socket?.remoteAddress ?? null;

  return normalizeIp(ip);
}
