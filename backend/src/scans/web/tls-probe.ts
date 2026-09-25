import { X509Certificate } from 'node:crypto';
import { isIP, Socket } from 'node:net';
import * as tls from 'node:tls';
import { CertificateInfo, TlsProbeInfo } from '../analyzers/tls.analyzer';

export interface TlsProbeOptions {
  address: string;
  port: number;
  /** Nombre del activo (SNI y verificación de identidad). */
  hostname: string;
  timeoutMs: number;
  signal: AbortSignal;
  /** Comprueba adicionalmente si el servidor acepta TLS 1.0/1.1. */
  checkLegacy?: boolean;
}

export type TlsProbeOutcome =
  | { ok: true; info: TlsProbeInfo }
  | { ok: false; error: string; code?: string; /** true si el puerto no acepta conexiones TCP. */ connectionRefused: boolean };

/** Tabla de OIDs de algoritmos de firma más habituales. */
const SIGNATURE_OIDS: Record<string, string> = {
  '1.2.840.113549.1.1.4': 'md5WithRSAEncryption',
  '1.2.840.113549.1.1.5': 'sha1WithRSAEncryption',
  '1.2.840.113549.1.1.11': 'sha256WithRSAEncryption',
  '1.2.840.113549.1.1.12': 'sha384WithRSAEncryption',
  '1.2.840.113549.1.1.13': 'sha512WithRSAEncryption',
  '1.2.840.113549.1.1.10': 'rsassaPss',
  '1.2.840.10045.4.1': 'ecdsa-with-SHA1',
  '1.2.840.10045.4.3.2': 'ecdsa-with-SHA256',
  '1.2.840.10045.4.3.3': 'ecdsa-with-SHA384',
  '1.2.840.10045.4.3.4': 'ecdsa-with-SHA512',
  '1.3.101.112': 'ed25519',
  '1.3.101.113': 'ed448',
};

/** Lee la longitud de un elemento DER y devuelve [longitud, bytes de cabecera]. */
function derLength(buf: Buffer, offset: number): [number, number] {
  const first = buf[offset + 1];
  if (first < 0x80) return [first, 2];
  const n = first & 0x7f;
  let len = 0;
  for (let i = 0; i < n; i += 1) len = (len << 8) | buf[offset + 2 + i];
  return [len, 2 + n];
}

function decodeOid(bytes: Buffer): string {
  const parts: number[] = [];
  let value = 0;
  for (let i = 0; i < bytes.length; i += 1) {
    value = value * 128 + (bytes[i] & 0x7f);
    if ((bytes[i] & 0x80) === 0) {
      if (parts.length === 0) {
        parts.push(Math.floor(value / 40), value % 40);
      } else {
        parts.push(value);
      }
      value = 0;
    }
  }
  return parts.join('.');
}

/**
 * Extrae el algoritmo de firma del certificado DER.
 * Certificate ::= SEQUENCE { tbsCertificate SEQUENCE, signatureAlgorithm SEQUENCE { OID ... }, signature }
 */
export function signatureAlgorithmFromDer(raw: Buffer): string | null {
  try {
    if (raw[0] !== 0x30) return null;
    const [, outerHeader] = derLength(raw, 0);
    let offset = outerHeader;
    if (raw[offset] !== 0x30) return null;
    const [tbsLen, tbsHeader] = derLength(raw, offset);
    offset += tbsHeader + tbsLen;
    if (raw[offset] !== 0x30) return null;
    const [, algHeader] = derLength(raw, offset);
    offset += algHeader;
    if (raw[offset] !== 0x06) return null;
    const [oidLen, oidHeader] = derLength(raw, offset);
    const oid = decodeOid(raw.subarray(offset + oidHeader, offset + oidHeader + oidLen));
    return SIGNATURE_OIDS[oid] ?? oid;
  } catch {
    return null;
  }
}

function describeCertificate(peer: tls.DetailedPeerCertificate): CertificateInfo {
  const x509 = new X509Certificate(peer.raw);
  const details = x509.publicKey.asymmetricKeyDetails ?? {};
  const keyType = x509.publicKey.asymmetricKeyType ?? null;
  const curve = (details as { namedCurve?: string }).namedCurve ?? null;
  let keyBits: number | null = (details as { modulusLength?: number }).modulusLength ?? null;
  if (keyBits === null && curve) {
    const m = /(\d{3})/.exec(curve);
    keyBits = m ? Number(m[1]) : null;
  }
  if (keyBits === null && keyType === 'ed25519') keyBits = 256;
  if (keyBits === null && keyType === 'ed448') keyBits = 448;

  return {
    subject: x509.subject.replace(/\n/g, ', '),
    issuer: x509.issuer.replace(/\n/g, ', '),
    subjectAltName: x509.subjectAltName ?? null,
    validFrom: x509.validFromDate.toISOString(),
    validTo: x509.validToDate.toISOString(),
    serialNumber: x509.serialNumber,
    fingerprint256: x509.fingerprint256,
    keyType,
    keyBits,
    curve,
    signatureAlgorithm: signatureAlgorithmFromDer(peer.raw),
    selfSigned: x509.subject === x509.issuer,
  };
}

function chainLength(peer: tls.DetailedPeerCertificate): number {
  let length = 0;
  let current: tls.DetailedPeerCertificate | undefined = peer;
  const seen = new Set<string>();
  while (current && current.fingerprint256 && !seen.has(current.fingerprint256)) {
    seen.add(current.fingerprint256);
    length += 1;
    current = current.issuerCertificate;
  }
  return length;
}

function connect(options: tls.ConnectionOptions, timeoutMs: number, signal: AbortSignal): Promise<tls.TLSSocket> {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(options);
    const onAbort = () => {
      socket.destroy();
      reject(Object.assign(new Error('Sondeo TLS abortado'), { code: 'ABORT_ERR' }));
    };
    signal.addEventListener('abort', onAbort, { once: true });
    socket.setTimeout(timeoutMs, () => {
      socket.destroy();
      reject(Object.assign(new Error('Tiempo de espera agotado en la conexión TLS'), { code: 'ETIMEDOUT' }));
    });
    socket.once('secureConnect', () => {
      signal.removeEventListener('abort', onAbort);
      resolve(socket);
    });
    socket.once('error', (err) => {
      signal.removeEventListener('abort', onAbort);
      reject(err);
    });
  });
}

/** Comprueba si el servidor negocia TLS 1.0/1.1. Devuelve la versión negociada o null. */
async function probeLegacy(options: TlsProbeOptions): Promise<{ supported: boolean | null; negotiated: string | null }> {
  try {
    const socket = await connect(
      {
        host: options.address,
        port: options.port,
        servername: isIP(options.hostname) ? undefined : options.hostname,
        rejectUnauthorized: false,
        minVersion: 'TLSv1',
        maxVersion: 'TLSv1.1',
        ciphers: 'DEFAULT:@SECLEVEL=0',
      },
      options.timeoutMs,
      options.signal,
    );
    const negotiated = socket.getProtocol();
    socket.destroy();
    return { supported: true, negotiated };
  } catch (err) {
    const code = (err as { code?: string }).code ?? '';
    // El servidor rechazó la versión: comprobación concluyente.
    if (/PROTOCOL_VERSION|UNSUPPORTED_PROTOCOL|HANDSHAKE_FAILURE|ECONNRESET|ALERT/.test(code) || /version/i.test((err as Error).message)) {
      return { supported: false, negotiated: null };
    }
    return { supported: null, negotiated: null };
  }
}

/** Comprueba si un puerto acepta conexiones TCP. */
export function tcpPortOpen(address: string, port: number, timeoutMs: number): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = new Socket();
    const done = (open: boolean) => {
      socket.destroy();
      resolve(open);
    };
    socket.setTimeout(timeoutMs, () => done(false));
    socket.once('connect', () => done(true));
    socket.once('error', () => done(false));
    socket.connect(port, address);
  });
}

/** Establece una conexión TLS y recopila certificado, protocolo y validación (RF-05). */
export async function tlsProbe(options: TlsProbeOptions): Promise<TlsProbeOutcome> {
  const hostIsIp = isIP(options.hostname) !== 0;
  let socket: tls.TLSSocket;
  try {
    socket = await connect(
      {
        host: options.address,
        port: options.port,
        servername: hostIsIp ? undefined : options.hostname,
        rejectUnauthorized: false,
        ALPNProtocols: ['http/1.1'],
      },
      options.timeoutMs,
      options.signal,
    );
  } catch (err) {
    const code = (err as { code?: string }).code;
    return {
      ok: false,
      error: (err as Error).message,
      code,
      connectionRefused: code === 'ECONNREFUSED' || code === 'EHOSTUNREACH' || code === 'ETIMEDOUT',
    };
  }

  try {
    const peer = socket.getPeerCertificate(true);
    if (!peer || !peer.raw) {
      return { ok: false, error: 'El servidor no presentó certificado', connectionRefused: false };
    }
    const hostnameError = tls.checkServerIdentity(options.hostname, peer)?.message ?? null;
    const info: TlsProbeInfo = {
      hostname: options.hostname,
      port: options.port,
      protocol: socket.getProtocol(),
      cipher: socket.getCipher()?.name ?? null,
      authorized: socket.authorized,
      authorizationError: socket.authorizationError ? String((socket.authorizationError as { code?: string }).code ?? socket.authorizationError) : null,
      hostnameError,
      legacyProtocolSupported: null,
      legacyProtocolNegotiated: null,
      certificate: describeCertificate(peer),
      chainLength: chainLength(peer),
    };
    socket.destroy();

    if (options.checkLegacy !== false) {
      const legacy = await probeLegacy(options);
      info.legacyProtocolSupported = legacy.supported;
      info.legacyProtocolNegotiated = legacy.negotiated;
    }
    return { ok: true, info };
  } catch (err) {
    socket.destroy();
    return { ok: false, error: (err as Error).message, code: (err as { code?: string }).code, connectionRefused: false };
  }
}
