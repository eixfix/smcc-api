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
var SecurityService_1;
Object.defineProperty(exports, "__esModule", { value: true });
exports.SecurityService = void 0;
const common_1 = require("@nestjs/common");
const client_1 = require("@prisma/client");
const node_dns_1 = require("node:dns");
const node_net_1 = require("node:net");
const node_tls_1 = require("node:tls");
const promises_1 = require("node:timers/promises");
const node_url_1 = require("node:url");
const credit_costs_1 = require("../../common/constants/credit-costs");
const prisma_service_1 = require("../../prisma/prisma.service");
const organization_credit_service_1 = require("../organization/organization-credit.service");
const SECURITY_HEADERS = [
    {
        name: 'strict-transport-security',
        recommendation: 'Enable HSTS to enforce HTTPS and protect against protocol downgrade attacks.'
    },
    {
        name: 'content-security-policy',
        recommendation: 'Define a Content-Security-Policy header to mitigate cross-site scripting and data injection.'
    },
    {
        name: 'x-content-type-options',
        recommendation: 'Add X-Content-Type-Options: nosniff to prevent MIME-type confusion attacks.'
    },
    {
        name: 'x-frame-options',
        recommendation: 'Add X-Frame-Options (or frame-ancestors in CSP) to defend against clickjacking.'
    },
    {
        name: 'referrer-policy',
        recommendation: 'Define a Referrer-Policy header to control sensitive data leakage via the Referer header.'
    },
    {
        name: 'permissions-policy',
        recommendation: 'Add a Permissions-Policy header to limit access to powerful browser features.'
    }
];
let SecurityService = SecurityService_1 = class SecurityService {
    constructor(prisma, creditService) {
        this.prisma = prisma;
        this.creditService = creditService;
        this.logger = new common_1.Logger(SecurityService_1.name);
    }
    async checkEndpoint(organizationId, url, user) {
        var _a, _b;
        await this.ensureUserExists(user);
        await this.verifyOrganizationAccess(organizationId, user);
        const parsedUrl = this.normalizeUrl(url);
        const abortController = new AbortController();
        const timeout = setTimeout(() => abortController.abort(), 10000);
        const warnings = [];
        let creditsDebited = false;
        try {
            await this.creditService.spendCredits(organizationId, credit_costs_1.CREDIT_COST_SECURITY_CHECK, undefined, 'run a security check');
            creditsDebited = true;
            const response = await fetch(parsedUrl, {
                method: 'GET',
                redirect: 'follow',
                signal: abortController.signal,
                headers: {
                    'User-Agent': 'LoadTestSecurityBot/1.0 (+https://loadtest.local)'
                }
            });
            const finalUrl = (_a = response.url) !== null && _a !== void 0 ? _a : parsedUrl;
            const usesHttps = finalUrl.startsWith('https://');
            if (!usesHttps) {
                warnings.push('Endpoint does not enforce HTTPS after redirects.');
            }
            const securityHeaders = this.evaluateSecurityHeaders(response);
            if (securityHeaders.some((header) => !header.present)) {
                warnings.push('One or more recommended security headers are missing.');
            }
            let tlsDetails = null;
            if (usesHttps) {
                try {
                    tlsDetails = await this.inspectTls(finalUrl);
                    if (tlsDetails === null || tlsDetails === void 0 ? void 0 : tlsDetails.isExpired) {
                        warnings.push('TLS certificate has expired.');
                    }
                    else if (tlsDetails && tlsDetails.daysUntilExpiry !== null && tlsDetails.daysUntilExpiry <= 30) {
                        warnings.push(`TLS certificate expires in ${tlsDetails.daysUntilExpiry} days.`);
                    }
                    if (tlsDetails === null || tlsDetails === void 0 ? void 0 : tlsDetails.authorizationError) {
                        warnings.push(`TLS authorization issue detected: ${tlsDetails.authorizationError}.`);
                    }
                }
                catch (error) {
                    this.logger.warn(`TLS inspection failed for ${finalUrl}: ${error.message}`);
                    warnings.push('Unable to inspect TLS configuration.');
                }
            }
            const contentType = (_b = response.headers.get('content-type')) !== null && _b !== void 0 ? _b : '';
            let metadata = {
                title: null,
                description: null,
                openGraphTitle: null,
                openGraphSiteName: null
            };
            if (contentType.includes('text/html')) {
                const text = await this.readLimitedText(response, 256000);
                metadata = this.extractMetadata(text);
            }
            else {
                warnings.push('Response is not HTML; metadata extraction skipped.');
            }
            const ownership = await this.lookupOwnership(parsedUrl, warnings).catch((error) => {
                this.logger.warn(`Ownership lookup failed for ${parsedUrl}: ${error.message}`);
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
        }
        catch (error) {
            if (error instanceof organization_credit_service_1.InsufficientCreditsException) {
                throw error;
            }
            if (creditsDebited) {
                await this.creditService
                    .refundCredits(organizationId, credit_costs_1.CREDIT_COST_SECURITY_CHECK)
                    .catch((refundError) => this.logger.error('Failed to refund credits after security check failure', refundError));
            }
            if (error instanceof Error && error.name === 'AbortError') {
                throw new common_1.BadRequestException('Security check timed out. Try again later.');
            }
            if (error instanceof common_1.BadRequestException) {
                throw error;
            }
            this.logger.error(`Security check failed for ${url}`, error);
            throw new common_1.BadRequestException('Unable to check the requested endpoint.');
        }
        finally {
            clearTimeout(timeout);
        }
    }
    async ensureUserExists(user) {
        if (user.role === client_1.Role.ADMINISTRATOR) {
            return;
        }
        const exists = await this.prisma.user.findUnique({
            where: { id: user.userId },
            select: { id: true }
        });
        if (!exists) {
            throw new common_1.BadRequestException('User context is invalid.');
        }
    }
    async verifyOrganizationAccess(organizationId, user) {
        const organization = await this.prisma.organization.findUnique({
            where: { id: organizationId },
            select: { id: true }
        });
        if (!organization) {
            throw new common_1.NotFoundException('Organization not found.');
        }
        if (user.role === client_1.Role.ADMINISTRATOR) {
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
            throw new common_1.ForbiddenException('You do not have access to this organization.');
        }
    }
    normalizeUrl(url) {
        const parsed = new node_url_1.URL(url);
        if (!['http:', 'https:'].includes(parsed.protocol)) {
            throw new common_1.BadRequestException('Only http and https schemes are supported.');
        }
        parsed.hash = '';
        return parsed.toString();
    }
    evaluateSecurityHeaders(response) {
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
    async readLimitedText(response, maxBytes) {
        const text = await response.text();
        if (text.length > maxBytes) {
            return text.slice(0, maxBytes);
        }
        return text;
    }
    extractMetadata(html) {
        const titleMatch = html.match(/<title>(.*?)<\/title>/i);
        const metaDescriptionMatch = html.match(/<meta\s+(?:name|property)="description"\s+content="([^"]*)"/i);
        const ogTitleMatch = html.match(/<meta\s+(?:name|property)="og:title"\s+content="([^"]*)"/i);
        const ogSiteNameMatch = html.match(/<meta\s+(?:name|property)="og:site_name"\s+content="([^"]*)"/i);
        return {
            title: this.sanitizeText(titleMatch ? this.decodeHtmlEntities(titleMatch[1]) : null),
            description: this.sanitizeText(metaDescriptionMatch ? this.decodeHtmlEntities(metaDescriptionMatch[1]) : null),
            openGraphTitle: this.sanitizeText(ogTitleMatch ? this.decodeHtmlEntities(ogTitleMatch[1]) : null),
            openGraphSiteName: this.sanitizeText(ogSiteNameMatch ? this.decodeHtmlEntities(ogSiteNameMatch[1]) : null)
        };
    }
    decodeHtmlEntities(value) {
        return value
            .replace(/&nbsp;/g, ' ')
            .replace(/&amp;/g, '&')
            .replace(/&lt;/g, '<')
            .replace(/&gt;/g, '>')
            .trim();
    }
    sanitizeText(value) {
        if (!value) {
            return null;
        }
        const trimmed = value.trim();
        if (!trimmed || /^\[object\s[a-zA-Z]+\]$/i.test(trimmed)) {
            return null;
        }
        return trimmed;
    }
    stripMailto(value) {
        return value.startsWith('mailto:') ? value.slice(7) : value;
    }
    async inspectTls(url) {
        const parsed = new node_url_1.URL(url);
        if (parsed.protocol !== 'https:') {
            return null;
        }
        const port = parsed.port ? Number(parsed.port) : 443;
        return new Promise((resolve, reject) => {
            const socket = (0, node_tls_1.connect)({
                host: parsed.hostname,
                port,
                servername: parsed.hostname,
                ALPNProtocols: ['http/1.1'],
                rejectUnauthorized: false
            }, () => {
                var _a, _b;
                try {
                    const protocol = socket.getProtocol();
                    const cipher = socket.getCipher();
                    const certificate = socket.getPeerCertificate(true);
                    const authorizationError = socket.authorized
                        ? null
                        : (_a = socket.authorizationError) !== null && _a !== void 0 ? _a : 'Unable to verify TLS certificate.';
                    const validFromIso = (certificate === null || certificate === void 0 ? void 0 : certificate.valid_from)
                        ? new Date(certificate.valid_from).toISOString()
                        : null;
                    const validToIso = (certificate === null || certificate === void 0 ? void 0 : certificate.valid_to)
                        ? new Date(certificate.valid_to).toISOString()
                        : null;
                    let daysUntilExpiry = null;
                    let isExpired = false;
                    if (validToIso) {
                        const expiryMs = Date.parse(validToIso);
                        if (Number.isFinite(expiryMs)) {
                            const diffDays = Math.floor((expiryMs - Date.now()) / (1000 * 60 * 60 * 24));
                            daysUntilExpiry = diffDays;
                            isExpired = diffDays < 0;
                        }
                    }
                    const subject = (certificate === null || certificate === void 0 ? void 0 : certificate.subject)
                        ? this.formatCertAttributes(certificate.subject)
                        : null;
                    const issuer = (certificate === null || certificate === void 0 ? void 0 : certificate.issuer)
                        ? this.formatCertAttributes(certificate.issuer)
                        : null;
                    const altNames = (certificate === null || certificate === void 0 ? void 0 : certificate.subjectaltname)
                        ? certificate.subjectaltname
                            .split(',')
                            .map((entry) => entry.trim().replace(/^DNS:/i, ''))
                            .filter(Boolean)
                        : [];
                    resolve({
                        protocol: protocol !== null && protocol !== void 0 ? protocol : null,
                        cipherSuite: (_b = cipher === null || cipher === void 0 ? void 0 : cipher.name) !== null && _b !== void 0 ? _b : null,
                        issuer: this.sanitizeText(issuer),
                        subject: this.sanitizeText(subject),
                        validFrom: validFromIso,
                        validTo: validToIso,
                        daysUntilExpiry,
                        isExpired,
                        authorizationError: typeof authorizationError === 'string'
                            ? this.sanitizeText(authorizationError)
                            : authorizationError
                                ? this.sanitizeText(String(authorizationError))
                                : null,
                        subjectAlternativeNames: altNames
                    });
                }
                catch (error) {
                    reject(error);
                }
                finally {
                    socket.end();
                }
            });
            socket.setTimeout(8000, () => {
                socket.destroy();
                reject(new Error('TLS handshake timed out'));
            });
            socket.once('error', (error) => {
                socket.destroy();
                reject(error);
            });
        });
    }
    formatCertAttributes(attributes) {
        return Object.entries(attributes)
            .map(([key, value]) => `${key}=${value}`)
            .join(', ');
    }
    async lookupWhois(hostname) {
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
        const registrar = this.sanitizeText(this.extractWhoisField(response, [
            'Registrar:',
            'Sponsoring Registrar:',
            'Registrar Name:'
        ]));
        const registrant = this.sanitizeText(this.extractWhoisField(response, [
            'Registrant Organization:',
            'Registrant:',
            'Registrant Name:'
        ]));
        if (!registrar && !registrant) {
            return null;
        }
        return { registrar, registrant };
    }
    extractTld(hostname) {
        const parts = hostname.split('.');
        return parts.length >= 2 ? parts[parts.length - 1].toLowerCase() : null;
    }
    async resolveWhoisServer(tld) {
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
    extractWhoisField(response, prefixes) {
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
    async lookupOwnership(url, warnings) {
        var _a, _b, _c, _d, _e, _f, _g, _h;
        const parsed = new node_url_1.URL(url);
        const hostname = parsed.hostname;
        let primaryNameServer = null;
        let responsibleEmail = null;
        try {
            const soa = await node_dns_1.promises.resolveSoa(hostname);
            primaryNameServer = (_a = soa.nsname) !== null && _a !== void 0 ? _a : null;
            responsibleEmail = soa.hostmaster ? this.normalizeSoaEmail(soa.hostmaster) : null;
        }
        catch (error) {
            this.logger.debug(`SOA lookup failed for ${hostname}: ${error.message}`);
            warnings.push('DNS SOA lookup failed; attempting RDAP registry lookup.');
        }
        const rdapDetails = await this.lookupRdap(hostname).catch((error) => {
            this.logger.warn(`RDAP lookup failed for ${hostname}: ${error.message}`);
            warnings.push('RDAP lookup unavailable; registrant details omitted.');
            return null;
        });
        const whoisDetails = await this.lookupWhois(hostname).catch((error) => {
            this.logger.debug(`WHOIS lookup failed for ${hostname}: ${error.message}`);
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
            registry: (_b = rdapDetails === null || rdapDetails === void 0 ? void 0 : rdapDetails.registry) !== null && _b !== void 0 ? _b : null,
            registrarName: (_c = rdapDetails === null || rdapDetails === void 0 ? void 0 : rdapDetails.registrarName) !== null && _c !== void 0 ? _c : null,
            registrarEmail: (_d = rdapDetails === null || rdapDetails === void 0 ? void 0 : rdapDetails.registrarEmail) !== null && _d !== void 0 ? _d : null,
            registrantName: (_e = rdapDetails === null || rdapDetails === void 0 ? void 0 : rdapDetails.registrantName) !== null && _e !== void 0 ? _e : null,
            registrantEmail: (_f = rdapDetails === null || rdapDetails === void 0 ? void 0 : rdapDetails.registrantEmail) !== null && _f !== void 0 ? _f : null,
            whoisRegistrar: (_g = whoisDetails === null || whoisDetails === void 0 ? void 0 : whoisDetails.registrar) !== null && _g !== void 0 ? _g : null,
            whoisRegistrant: (_h = whoisDetails === null || whoisDetails === void 0 ? void 0 : whoisDetails.registrant) !== null && _h !== void 0 ? _h : null
        };
    }
    normalizeSoaEmail(value) {
        if (!value.includes('.')) {
            return value;
        }
        const atIndex = value.indexOf('.');
        return `${value.slice(0, atIndex)}@${value.slice(atIndex + 1)}`;
    }
    async lookupRdap(hostname) {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 10000);
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
            const payload = (await response.json());
            if (!payload || typeof payload !== 'object') {
                return null;
            }
            const rdap = payload;
            const entities = this.normalizeEntities(rdap.entities);
            const registrar = this.findEntity(entities, ['registrar']);
            const registrant = this.findEntity(entities, ['registrant', 'administrative', 'technical']);
            return {
                registry: this.sanitizeText(typeof rdap.port43 === 'string' ? rdap.port43 : null),
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
        }
        finally {
            clearTimeout(timeout);
        }
    }
    normalizeEntities(input) {
        if (!Array.isArray(input)) {
            return [];
        }
        return input
            .map((entity) => this.normalizeEntity(entity))
            .filter((entity) => entity !== null);
    }
    normalizeEntity(entity) {
        if (!entity || typeof entity !== 'object') {
            return null;
        }
        const record = entity;
        const rolesValue = record.roles;
        const roles = Array.isArray(rolesValue)
            ? rolesValue.filter((role) => typeof role === 'string')
            : [];
        const vcardArray = record.vcardArray;
        return {
            roles,
            vcardArray
        };
    }
    findEntity(entities, roleCandidates) {
        var _a;
        return ((_a = entities.find((entity) => entity.roles.some((role) => roleCandidates.includes(role.toLowerCase())))) !== null && _a !== void 0 ? _a : null);
    }
    extractVcardValue(vcardArray, key) {
        if (!Array.isArray(vcardArray) || vcardArray.length < 2) {
            return null;
        }
        const entriesRaw = vcardArray[1];
        if (!Array.isArray(entriesRaw)) {
            return null;
        }
        const entries = entriesRaw;
        const lowerKey = key.toLowerCase();
        for (const entry of entries) {
            if (!Array.isArray(entry) || entry.length < 4) {
                continue;
            }
            const [entryKey, , , value] = entry;
            if (typeof entryKey !== 'string' || entryKey.toLowerCase() !== lowerKey) {
                continue;
            }
            if (typeof value === 'string') {
                return this.stripMailto(value);
            }
            if (value && typeof value === 'object') {
                const candidate = value;
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
    async queryWhois(server, query) {
        const socket = new node_net_1.Socket();
        try {
            const result = await Promise.race([
                new Promise((resolve, reject) => {
                    let data = '';
                    socket.setTimeout(8000);
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
                (0, promises_1.setTimeout)(9000).then(() => {
                    socket.destroy();
                    return null;
                })
            ]);
            return result;
        }
        finally {
            if (!socket.destroyed) {
                socket.destroy();
            }
        }
    }
};
exports.SecurityService = SecurityService;
exports.SecurityService = SecurityService = SecurityService_1 = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [prisma_service_1.PrismaService,
        organization_credit_service_1.OrganizationCreditService])
], SecurityService);
//# sourceMappingURL=security.service.js.map