import {
  BadRequestException,
  Injectable,
  Logger,
  NotFoundException,
  ForbiddenException
} from '@nestjs/common';
import { Role } from '@prisma/client';
import { promises as dns, type SoaRecord } from 'node:dns';
import { Socket } from 'node:net';
import { connect as tlsConnect } from 'node:tls';
import { setTimeout as setTimeoutPromise } from 'node:timers/promises';
import { URL } from 'node:url';

import type { AuthenticatedUser } from '../../common/types/auth-user';
import { CREDIT_COST_SECURITY_CHECK } from '../../common/constants/credit-costs';
import { PrismaService } from '../../prisma/prisma.service';
import {
  InsufficientCreditsException,
  OrganizationCreditService
} from '../organization/organization-credit.service';
import type {
  MetadataSummary,
  OwnershipSummary,
  SecurityCheckResult,
  SecurityHeaderCheck,
  TlsInspection
} from './types';

type HttpResponse = globalThis.Response;

const SECURITY_HEADERS: Array<{ name: string; recommendation: string }> = [
  {
    name: 'strict-transport-security',
    recommendation: 'Enable HSTS to enforce HTTPS and protect against protocol downgrade attacks.'
  },
  {
    name: 'content-security-policy',
    recommendation:
      'Define a Content-Security-Policy header to mitigate cross-site scripting and data injection.'
  },
  {
    name: 'x-content-type-options',
    recommendation: 'Add X-Content-Type-Options: nosniff to prevent MIME-type confusion attacks.'
  },
  {
    name: 'x-frame-options',
    recommendation:
      'Add X-Frame-Options (or frame-ancestors in CSP) to defend against clickjacking.'
  },
  {
    name: 'referrer-policy',
    recommendation:
      'Define a Referrer-Policy header to control sensitive data leakage via the Referer header.'
  },
  {
    name: 'permissions-policy',
    recommendation:
      'Add a Permissions-Policy header to limit access to powerful browser features.'
  }
];

@Injectable()
export class SecurityService {
  private readonly logger = new Logger(SecurityService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly creditService: OrganizationCreditService
  ) {}

  async checkEndpoint(
    organizationId: string,
    url: string,
    user: AuthenticatedUser
  ): Promise<SecurityCheckResult> {
    await this.ensureUserExists(user);
    await this.verifyOrganizationAccess(organizationId, user);

    const parsedUrl = this.normalizeUrl(url);
    const abortController = new AbortController();
    const timeout = setTimeout(() => abortController.abort(), 10_000);
    const warnings: string[] = [];
    let creditsDebited = false;

    try {
      await this.creditService.spendCredits(
        organizationId,
        CREDIT_COST_SECURITY_CHECK,
        undefined,
        'run a security check'
      );
      creditsDebited = true;

      const response = await fetch(parsedUrl, {
        method: 'GET',
        redirect: 'follow',
        signal: abortController.signal,
        headers: {
          'User-Agent': 'LoadTestSecurityBot/1.0 (+https://loadtest.local)'
        }
      });

      const finalUrl = response.url ?? parsedUrl;
      const usesHttps = finalUrl.startsWith('https://');
      if (!usesHttps) {
        warnings.push('Endpoint does not enforce HTTPS after redirects.');
      }

      const securityHeaders = this.evaluateSecurityHeaders(response);

      if (securityHeaders.some((header) => !header.present)) {
        warnings.push('One or more recommended security headers are missing.');
      }

      let tlsDetails: TlsInspection | null = null;

      if (usesHttps) {
        try {
          tlsDetails = await this.inspectTls(finalUrl);

          if (tlsDetails?.isExpired) {
            warnings.push('TLS certificate has expired.');
          } else if (tlsDetails && tlsDetails.daysUntilExpiry !== null && tlsDetails.daysUntilExpiry <= 30) {
            warnings.push(`TLS certificate expires in ${tlsDetails.daysUntilExpiry} days.`);
          }

          if (tlsDetails?.authorizationError) {
            warnings.push(`TLS authorization issue detected: ${tlsDetails.authorizationError}.`);
          }
        } catch (error) {
          this.logger.warn(
            `TLS inspection failed for ${finalUrl}: ${(error as Error).message}`
          );
          warnings.push('Unable to inspect TLS configuration.');
        }
      }

      const contentType = response.headers.get('content-type') ?? '';
      let metadata: MetadataSummary = {
        title: null,
        description: null,
        openGraphTitle: null,
        openGraphSiteName: null
      };

      if (contentType.includes('text/html')) {
        const text = await this.readLimitedText(response, 256_000);
        metadata = this.extractMetadata(text);
      } else {
        warnings.push('Response is not HTML; metadata extraction skipped.');
      }

      const ownership = await this.lookupOwnership(parsedUrl, warnings).catch((error: unknown) => {
        this.logger.warn(`Ownership lookup failed for ${parsedUrl}: ${(error as Error).message}`);
        warnings.push('Unable to resolve domain ownership details.');
        return null;
      });

      return {
        requestedUrl: url,
        finalUrl,
        statusCode: response.status,
        usesHttps,
        securityHeaders,
        metadata,
        ownership,
        tls: tlsDetails,
        warnings,
        fetchedAt: new Date().toISOString()
      };
    } catch (error) {
      if (error instanceof InsufficientCreditsException) {
        throw error;
      }

      if (creditsDebited) {
        await this.creditService
          .refundCredits(organizationId, CREDIT_COST_SECURITY_CHECK)
          .catch((refundError) =>
            this.logger.error('Failed to refund credits after security check failure', refundError as Error)
          );
      }

      if (error instanceof Error && error.name === 'AbortError') {
        throw new BadRequestException('Security check timed out. Try again later.');
      }

      if (error instanceof BadRequestException) {
        throw error;
      }

      this.logger.error(`Security check failed for ${url}`, error as Error);
      throw new BadRequestException('Unable to check the requested endpoint.');
    } finally {
      clearTimeout(timeout);
    }
  }

  private async ensureUserExists(user: AuthenticatedUser): Promise<void> {
    if (user.role === Role.ADMINISTRATOR) {
      return;
    }

    const exists = await this.prisma.user.findUnique({
      where: { id: user.userId },
      select: { id: true }
    });

    if (!exists) {
      throw new BadRequestException('User context is invalid.');
    }
  }

  private async verifyOrganizationAccess(
    organizationId: string,
    user: AuthenticatedUser
  ): Promise<void> {
    const organization = await this.prisma.organization.findUnique({
      where: { id: organizationId },
      select: { id: true }
    });

    if (!organization) {
      throw new NotFoundException('Organization not found.');
    }

    if (user.role === Role.ADMINISTRATOR) {
      return;
    }

    const membership = await this.prisma.organizationMember.findFirst({
      where: {
        organizationId,
        userId: user.userId
      },
      select: { id: true }
    });

    if (!membership) {
      throw new ForbiddenException('You do not have access to this organization.');
    }
  }

  private normalizeUrl(url: string): string {
    const parsed = new URL(url);
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      throw new BadRequestException('Only http and https schemes are supported.');
    }
    parsed.hash = '';
    return parsed.toString();
  }

  private evaluateSecurityHeaders(response: HttpResponse): SecurityHeaderCheck[] {
    return SECURITY_HEADERS.map(({ name, recommendation }) => {
      const value = response.headers.get(name);
      return {
        header: name,
        present: Boolean(value),
        value,
        recommendation
      };
    });
  }

  private async readLimitedText(response: HttpResponse, maxBytes: number): Promise<string> {
    const text = await response.text();
    if (text.length > maxBytes) {
      return text.slice(0, maxBytes);
    }
    return text;
  }

  private extractMetadata(html: string): MetadataSummary {
    const titleMatch = html.match(/<title>(.*?)<\/title>/i);
    const metaDescriptionMatch = html.match(
      /<meta\s+(?:name|property)="description"\s+content="([^"]*)"/i
    );
    const ogTitleMatch = html.match(
      /<meta\s+(?:name|property)="og:title"\s+content="([^"]*)"/i
    );
    const ogSiteNameMatch = html.match(
      /<meta\s+(?:name|property)="og:site_name"\s+content="([^"]*)"/i
    );

    return {
      title: this.sanitizeText(titleMatch ? this.decodeHtmlEntities(titleMatch[1]) : null),
      description: this.sanitizeText(
        metaDescriptionMatch ? this.decodeHtmlEntities(metaDescriptionMatch[1]) : null
      ),
      openGraphTitle: this.sanitizeText(
        ogTitleMatch ? this.decodeHtmlEntities(ogTitleMatch[1]) : null
      ),
      openGraphSiteName: this.sanitizeText(
        ogSiteNameMatch ? this.decodeHtmlEntities(ogSiteNameMatch[1]) : null
      )
    };
  }

  private decodeHtmlEntities(value: string): string {
    return value
      .replace(/&nbsp;/g, ' ')
      .replace(/&amp;/g, '&')
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .trim();
  }

  private sanitizeText(value: string | null): string | null {
    if (!value) {
      return null;
    }

    const trimmed = value.trim();
    if (!trimmed || /^\[object\s[a-zA-Z]+\]$/i.test(trimmed)) {
      return null;
    }

    return trimmed;
  }

  private stripMailto(value: string): string {
    return value.startsWith('mailto:') ? value.slice(7) : value;
  }

  private async inspectTls(url: string): Promise<TlsInspection | null> {
    const parsed = new URL(url);
    if (parsed.protocol !== 'https:') {
      return null;
    }

    const port = parsed.port ? Number(parsed.port) : 443;

    return new Promise((resolve, reject) => {
      const socket = tlsConnect(
        {
          host: parsed.hostname,
          port,
          servername: parsed.hostname,
          ALPNProtocols: ['http/1.1'],
          rejectUnauthorized: false
        },
        () => {
          try {
            const protocol = socket.getProtocol();
            const cipher = socket.getCipher();
            const certificate = socket.getPeerCertificate(true);
            const authorizationError = socket.authorized
              ? null
              : socket.authorizationError ?? 'Unable to verify TLS certificate.';

            const validFromIso = certificate?.valid_from
              ? new Date(certificate.valid_from).toISOString()
              : null;
            const validToIso = certificate?.valid_to
              ? new Date(certificate.valid_to).toISOString()
              : null;

            let daysUntilExpiry: number | null = null;
            let isExpired = false;

            if (validToIso) {
              const expiryMs = Date.parse(validToIso);
              if (Number.isFinite(expiryMs)) {
                const diffDays = Math.floor((expiryMs - Date.now()) / (1000 * 60 * 60 * 24));
                daysUntilExpiry = diffDays;
                isExpired = diffDays < 0;
              }
            }

            const subject = certificate?.subject
              ? this.formatCertAttributes(certificate.subject as unknown as Record<string, string>)
              : null;
            const issuer = certificate?.issuer
              ? this.formatCertAttributes(certificate.issuer as unknown as Record<string, string>)
              : null;

            const altNames: string[] = certificate?.subjectaltname
              ? certificate.subjectaltname
                  .split(',')
                  .map((entry: string) => entry.trim().replace(/^DNS:/i, ''))
                  .filter(Boolean)
              : [];

            resolve({
              protocol: protocol ?? null,
              cipherSuite: cipher?.name ?? null,
              issuer: this.sanitizeText(issuer),
              subject: this.sanitizeText(subject),
              validFrom: validFromIso,
              validTo: validToIso,
              daysUntilExpiry,
              isExpired,
              authorizationError:
                typeof authorizationError === 'string'
                  ? this.sanitizeText(authorizationError)
                  : authorizationError
                    ? this.sanitizeText(String(authorizationError))
                    : null,
              subjectAlternativeNames: altNames
            });
          } catch (error) {
            reject(error);
          } finally {
            socket.end();
          }
        }
      );

      socket.setTimeout(8_000, () => {
        socket.destroy();
        reject(new Error('TLS handshake timed out'));
      });

      socket.once('error', (error) => {
        socket.destroy();
        reject(error);
      });
    });
  }

  private formatCertAttributes(attributes: Record<string, string>): string {
    return Object.entries(attributes)
      .map(([key, value]) => `${key}=${value}`)
      .join(', ');
  }

  private async lookupWhois(
    hostname: string
  ): Promise<{ registrar: string | null; registrant: string | null } | null> {
    const tld = this.extractTld(hostname);
    if (!tld) {
      return null;
    }

    const referralServer = await this.resolveWhoisServer(tld);
    if (!referralServer) {
      return null;
    }

    const response = await this.queryWhois(referralServer, hostname);
    if (!response) {
      return null;
    }

    const registrar = this.sanitizeText(
      this.extractWhoisField(response, [
        'Registrar:',
        'Sponsoring Registrar:',
        'Registrar Name:'
      ])
    );
    const registrant = this.sanitizeText(
      this.extractWhoisField(response, [
        'Registrant Organization:',
        'Registrant:',
        'Registrant Name:'
      ])
    );

    if (!registrar && !registrant) {
      return null;
    }

    return { registrar, registrant };
  }

  private extractTld(hostname: string): string | null {
    const parts = hostname.split('.');
    return parts.length >= 2 ? parts[parts.length - 1].toLowerCase() : null;
  }

  private async resolveWhoisServer(tld: string): Promise<string | null> {
    const response = await this.queryWhois('whois.iana.org', tld.toUpperCase());
    if (!response) {
      return null;
    }

    const referMatch = response.match(/^refer:\s*(.+)$/im);
    if (referMatch && referMatch[1]) {
      return referMatch[1].trim();
    }

    return null;
  }

  private extractWhoisField(response: string, prefixes: string[]): string | null {
    const lines = response.split(/\r?\n/);
    for (const line of lines) {
      for (const prefix of prefixes) {
        if (line.toLowerCase().startsWith(prefix.toLowerCase())) {
          const value = line.slice(prefix.length).trim();
          if (value) {
            return value;
          }
        }
      }
    }
    return null;
  }

  private async lookupOwnership(url: string, warnings: string[]): Promise<OwnershipSummary | null> {
    const parsed = new URL(url);
    const hostname = parsed.hostname;

    let primaryNameServer: string | null = null;
    let responsibleEmail: string | null = null;

    try {
      const soa: SoaRecord = await dns.resolveSoa(hostname);
      primaryNameServer = soa.nsname ?? null;
      responsibleEmail = soa.hostmaster ? this.normalizeSoaEmail(soa.hostmaster) : null;
    } catch (error) {
      this.logger.debug(`SOA lookup failed for ${hostname}: ${(error as Error).message}`);
      warnings.push('DNS SOA lookup failed; attempting RDAP registry lookup.');
    }

    const rdapDetails = await this.lookupRdap(hostname).catch((error: unknown) => {
      this.logger.warn(`RDAP lookup failed for ${hostname}: ${(error as Error).message}`);
      warnings.push('RDAP lookup unavailable; registrant details omitted.');
      return null;
    });

    const whoisDetails = await this.lookupWhois(hostname).catch((error: unknown) => {
      this.logger.debug(`WHOIS lookup failed for ${hostname}: ${(error as Error).message}`);
      warnings.push('WHOIS lookup unavailable; registrar snapshot omitted.');
      return null;
    });

    if (!primaryNameServer && !responsibleEmail && !rdapDetails && !whoisDetails) {
      return null;
    }

    return {
      domain: hostname,
      primaryNameServer: this.sanitizeText(primaryNameServer),
      responsibleEmail: this.sanitizeText(responsibleEmail),
      registry: rdapDetails?.registry ?? null,
      registrarName: rdapDetails?.registrarName ?? null,
      registrarEmail: rdapDetails?.registrarEmail ?? null,
      registrantName: rdapDetails?.registrantName ?? null,
      registrantEmail: rdapDetails?.registrantEmail ?? null,
      whoisRegistrar: whoisDetails?.registrar ?? null,
      whoisRegistrant: whoisDetails?.registrant ?? null
    };
  }

  private normalizeSoaEmail(value: string): string {
    if (!value.includes('.')) {
      return value;
    }

    const atIndex = value.indexOf('.');
    return `${value.slice(0, atIndex)}@${value.slice(atIndex + 1)}`;
  }

  private async lookupRdap(
    hostname: string
  ): Promise<{
    registry: string | null;
    registrarName: string | null;
    registrarEmail: string | null;
    registrantName: string | null;
    registrantEmail: string | null;
  } | null> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10_000);

    try {
      const endpoint = `https://rdap.org/domain/${hostname}`;
      const response = await fetch(endpoint, {
        headers: {
          'Content-Type': 'application/rdap+json',
          'User-Agent': 'LoadTestSecurityBot/1.0 (+https://loadtest.local)'
        },
        signal: controller.signal
      });

      if (!response.ok) {
        return null;
      }

      const payload = (await response.json()) as unknown;
      if (!payload || typeof payload !== 'object') {
        return null;
      }

      const rdap = payload as Record<string, unknown>;
      const entities = this.normalizeEntities(rdap.entities);
      const registrar = this.findEntity(entities, ['registrar']);
      const registrant = this.findEntity(entities, ['registrant', 'administrative', 'technical']);

      return {
        registry: this.sanitizeText(
          typeof rdap.port43 === 'string' ? rdap.port43 : null
        ),
        registrarName: registrar
          ? this.sanitizeText(this.extractVcardValue(registrar.vcardArray, 'fn'))
          : null,
        registrarEmail: registrar
          ? this.sanitizeText(this.extractVcardValue(registrar.vcardArray, 'email'))
          : null,
        registrantName: registrant
          ? this.sanitizeText(this.extractVcardValue(registrant.vcardArray, 'fn'))
          : null,
        registrantEmail: registrant
          ? this.sanitizeText(this.extractVcardValue(registrant.vcardArray, 'email'))
          : null
      };
    } finally {
      clearTimeout(timeout);
    }
  }

  private normalizeEntities(input: unknown): NormalizedRdapEntity[] {
    if (!Array.isArray(input)) {
      return [];
    }

    return input
      .map((entity) => this.normalizeEntity(entity))
      .filter((entity): entity is NormalizedRdapEntity => entity !== null);
  }

  private normalizeEntity(entity: unknown): NormalizedRdapEntity | null {
    if (!entity || typeof entity !== 'object') {
      return null;
    }

    const record = entity as Record<string, unknown>;
    const rolesValue = record.roles;
    const roles = Array.isArray(rolesValue)
      ? rolesValue.filter((role): role is string => typeof role === 'string')
      : [];

    const vcardArray = record.vcardArray;

    return {
      roles,
      vcardArray
    };
  }

  private findEntity(
    entities: NormalizedRdapEntity[],
    roleCandidates: string[]
  ): NormalizedRdapEntity | null {
    return (
      entities.find((entity) =>
        entity.roles.some((role) => roleCandidates.includes(role.toLowerCase()))
      ) ?? null
    );
  }

  private extractVcardValue(vcardArray: unknown, key: string): string | null {
    if (!Array.isArray(vcardArray) || vcardArray.length < 2) {
      return null;
    }

    const entriesRaw = vcardArray[1] as unknown;
    if (!Array.isArray(entriesRaw)) {
      return null;
    }

    const entries = entriesRaw as unknown[];
    const lowerKey = key.toLowerCase();

    for (const entry of entries) {
      if (!Array.isArray(entry) || entry.length < 4) {
        continue;
      }

      const [entryKey, , , value] = entry as [unknown, unknown, unknown, unknown];
      if (typeof entryKey !== 'string' || entryKey.toLowerCase() !== lowerKey) {
        continue;
      }

      if (typeof value === 'string') {
        return this.stripMailto(value);
      }

      if (value && typeof value === 'object') {
        const candidate = value as Record<string, unknown>;
        if (typeof candidate.text === 'string') {
          return candidate.text;
        }

        if (typeof candidate.uri === 'string') {
          return this.stripMailto(candidate.uri);
        }
      }
    }

    return null;
  }

  private async queryWhois(server: string, query: string): Promise<string | null> {
    const socket = new Socket();

    try {
      const result = await Promise.race<string | null>([
        new Promise<string | null>((resolve, reject) => {
          let data = '';

          socket.setTimeout(8_000);
          socket.once('timeout', () => {
            socket.destroy();
            reject(new Error('WHOIS connection timed out'));
          });
          socket.once('error', reject);
          socket.connect(43, server, () => {
            socket.write(`${query}\r\n`);
          });
          socket.on('data', (chunk) => {
            data += chunk.toString('utf-8');
          });
          socket.once('close', () => {
            resolve(data.length > 0 ? data : null);
          });
        }),
        setTimeoutPromise(9_000).then(() => {
          socket.destroy();
          return null;
        })
      ]);

      return result;
    } finally {
      if (!socket.destroyed) {
        socket.destroy();
      }
    }
  }
}

type NormalizedRdapEntity = {
  roles: string[];
  vcardArray: unknown;
};
