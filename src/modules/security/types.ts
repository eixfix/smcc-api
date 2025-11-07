export type SecurityHeaderCheck = {
  header: string;
  present: boolean;
  value: string | null;
  recommendation: string;
};

export type MetadataSummary = {
  title: string | null;
  description: string | null;
  openGraphTitle: string | null;
  openGraphSiteName: string | null;
};

export type OwnershipSummary = {
  domain: string;
  primaryNameServer: string | null;
  responsibleEmail: string | null;
  registry: string | null;
  registrarName: string | null;
  registrarEmail: string | null;
  registrantName: string | null;
  registrantEmail: string | null;
  whoisRegistrar: string | null;
  whoisRegistrant: string | null;
};

export type TlsInspection = {
  protocol: string | null;
  cipherSuite: string | null;
  issuer: string | null;
  subject: string | null;
  validFrom: string | null;
  validTo: string | null;
  daysUntilExpiry: number | null;
  isExpired: boolean;
  authorizationError: string | null;
  subjectAlternativeNames: string[];
};

export type SecurityCheckResult = {
  requestedUrl: string;
  finalUrl: string;
  statusCode: number;
  usesHttps: boolean;
  securityHeaders: SecurityHeaderCheck[];
  metadata: MetadataSummary;
  ownership: OwnershipSummary | null;
  tls: TlsInspection | null;
  warnings: string[];
  fetchedAt: string;
};
