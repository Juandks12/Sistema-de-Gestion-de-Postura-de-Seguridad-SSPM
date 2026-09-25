import { FindingDraft } from '../scanner.interface';

export interface CertificateInfo {
  subject: string;
  issuer: string;
  subjectAltName: string | null;
  validFrom: string;
  validTo: string;
  serialNumber: string;
  fingerprint256: string;
  keyType: string | null;
  /** Bits de la clave RSA/DSA o de la curva EC. */
  keyBits: number | null;
  curve: string | null;
  /** Nombre del algoritmo de firma, p. ej. sha256WithRSAEncryption. */
  signatureAlgorithm: string | null;
  selfSigned: boolean;
}

export interface TlsProbeInfo {
  hostname: string;
  port: number;
  protocol: string | null;
  cipher: string | null;
  authorized: boolean;
  authorizationError: string | null;
  /** Error de tls.checkServerIdentity, si lo hay. */
  hostnameError: string | null;
  /** true si el servidor negocia TLS 1.0/1.1; null si no se pudo comprobar. */
  legacyProtocolSupported: boolean | null;
  legacyProtocolNegotiated: string | null;
  certificate: CertificateInfo;
  chainLength: number;
}

const DAY_MS = 24 * 60 * 60 * 1000;

const WEAK_SIGNATURE_RE = /(md2|md5|sha1)/i;

/** Evalúa el resultado de una conexión TLS (RF-05). Función pura. */
export function analyzeTls(info: TlsProbeInfo, now: Date = new Date()): FindingDraft[] {
  const findings: FindingDraft[] = [];
  const location = `tls://${info.hostname}:${info.port}`;
  const cert = info.certificate;
  const validFrom = new Date(cert.validFrom);
  const validTo = new Date(cert.validTo);
  const daysLeft = Math.floor((validTo.getTime() - now.getTime()) / DAY_MS);

  const base = {
    subject: cert.subject,
    issuer: cert.issuer,
    validFrom: cert.validFrom,
    validTo: cert.validTo,
    daysUntilExpiry: daysLeft,
    fingerprint256: cert.fingerprint256,
    protocol: info.protocol,
    cipher: info.cipher,
  };

  if (validTo.getTime() < now.getTime()) {
    findings.push({ ruleId: 'TLS-EXPIRED', location, evidence: base });
  } else if (daysLeft < 7) {
    findings.push({ ruleId: 'TLS-EXPIRING-7D', location, evidence: base });
  } else if (daysLeft < 30) {
    findings.push({ ruleId: 'TLS-EXPIRING-30D', location, evidence: base });
  }

  if (validFrom.getTime() > now.getTime()) {
    findings.push({ ruleId: 'TLS-NOT-YET-VALID', location, evidence: base });
  }

  if (info.hostnameError) {
    findings.push({
      ruleId: 'TLS-HOSTNAME-MISMATCH',
      location,
      evidence: { ...base, subjectAltName: cert.subjectAltName, error: info.hostnameError },
    });
  }

  const chainErrors = new Set([
    'SELF_SIGNED_CERT_IN_CHAIN',
    'DEPTH_ZERO_SELF_SIGNED_CERT',
    'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
    'UNABLE_TO_GET_ISSUER_CERT',
    'UNABLE_TO_GET_ISSUER_CERT_LOCALLY',
    'CERT_UNTRUSTED',
    'CERT_SIGNATURE_FAILURE',
  ]);
  if (!info.authorized && info.authorizationError && chainErrors.has(info.authorizationError)) {
    findings.push({
      ruleId: 'TLS-UNTRUSTED-CHAIN',
      location,
      evidence: { ...base, error: info.authorizationError, selfSigned: cert.selfSigned, chainLength: info.chainLength },
    });
  }

  if (info.legacyProtocolSupported) {
    findings.push({
      ruleId: 'TLS-LEGACY-PROTOCOL',
      location,
      evidence: { ...base, negotiated: info.legacyProtocolNegotiated },
    });
  }

  if (cert.keyBits !== null) {
    const weak =
      (cert.keyType === 'rsa' || cert.keyType === 'dsa' || cert.keyType === 'rsa-pss') && cert.keyBits < 2048
        ? true
        : cert.keyType === 'ec' && cert.keyBits < 256;
    if (weak) {
      findings.push({
        ruleId: 'TLS-WEAK-KEY',
        location,
        evidence: { ...base, keyType: cert.keyType, keyBits: cert.keyBits, curve: cert.curve },
      });
    }
  }

  if (cert.signatureAlgorithm && WEAK_SIGNATURE_RE.test(cert.signatureAlgorithm)) {
    findings.push({
      ruleId: 'TLS-WEAK-SIGNATURE',
      location,
      evidence: { ...base, signatureAlgorithm: cert.signatureAlgorithm },
    });
  }

  return findings;
}
