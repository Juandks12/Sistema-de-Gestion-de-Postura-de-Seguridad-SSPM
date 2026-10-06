export interface DnssecDsRecord {
  keyTag: number;
  algorithm: number;
  digestType: number;
  digest: string;
  raw: string;
}

export interface DnssecDnskeyRecord {
  flags: number;
  protocol: number;
  algorithm: number;
  publicKey: string;
  raw: string;
}

export type DnssecStatus = 'secure' | 'insecure' | 'bogus' | 'indeterminate';

export interface DnssecResult {
  status: DnssecStatus;
  domain: string;
  adFlag: boolean;
  dsRecords: DnssecDsRecord[];
  dnskeyRecords: DnssecDnskeyRecord[];
  rrsigCount: number;
  error?: string;
}

export interface DohAnswer {
  name: string;
  type: number;
  TTL: number;
  data: string;
}

export interface DohResponse {
  Status: number;
  TC?: boolean;
  RD?: boolean;
  RA?: boolean;
  AD?: boolean;
  CD?: boolean;
  Question?: Array<{ name: string; type: number }>;
  Answer?: DohAnswer[];
  Authority?: DohAnswer[];
  Comment?: string;
}

export type DohQueryFn = (
  name: string,
  type: 'DS' | 'DNSKEY',
  signal?: AbortSignal,
) => Promise<DohResponse>;

export const DOH_QUERY = Symbol('DOH_QUERY');

const DOH_TIMEOUT_MS = 5000;

export function parseDsRecord(data: string): DnssecDsRecord | null {
  const parts = data.trim().split(/\s+/);
  if (parts.length < 4) return null;
  const keyTag = Number(parts[0]);
  const algorithm = Number(parts[1]);
  const digestType = Number(parts[2]);
  const digest = parts.slice(3).join('');
  if (Number.isNaN(keyTag) || Number.isNaN(algorithm) || Number.isNaN(digestType)) return null;
  return { keyTag, algorithm, digestType, digest, raw: data };
}

export function parseDnskeyRecord(data: string): DnssecDnskeyRecord | null {
  const parts = data.trim().split(/\s+/);
  if (parts.length < 4) return null;
  const flags = Number(parts[0]);
  const protocol = Number(parts[1]);
  const algorithm = Number(parts[2]);
  const publicKey = parts.slice(3).join('');
  if (Number.isNaN(flags) || Number.isNaN(protocol) || Number.isNaN(algorithm)) return null;
  return { flags, protocol, algorithm, publicKey, raw: data };
}

/**
 * Consulta DoH por defecto hacia Cloudflare con fallback a Google (RFC 8484).
 */
export const defaultDohQuery: DohQueryFn = async (
  name: string,
  type: 'DS' | 'DNSKEY',
  signal?: AbortSignal,
): Promise<DohResponse> => {
  const urlCloudflare = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}&do=1`;
  const urlGoogle = `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}&do=1`;

  const abortSignals = [AbortSignal.timeout(DOH_TIMEOUT_MS)];
  if (signal) abortSignals.push(signal);
  const combinedSignal = AbortSignal.any(abortSignals);

  try {
    const res = await fetch(urlCloudflare, {
      headers: { accept: 'application/dns-json' },
      signal: combinedSignal,
    });
    if (res.ok) {
      return (await res.json()) as DohResponse;
    }
  } catch {
    // Si falla Cloudflare, intentamos fallback con Google
  }

  const res = await fetch(urlGoogle, {
    headers: { accept: 'application/json' },
    signal: combinedSignal,
  });
  if (!res.ok) {
    throw new Error(`Error en consulta DoH: HTTP ${res.status}`);
  }
  return (await res.json()) as DohResponse;
};

/**
 * Valida la configuración DNSSEC del dominio (RFC 4033, 4034, 4035) consultando
 * los registros DS, DNSKEY y la bandera AD (Authenticated Data).
 */
export async function lookupDnssec(
  domain: string,
  dohQuery: DohQueryFn = defaultDohQuery,
  signal?: AbortSignal,
): Promise<DnssecResult> {
  const cleanDomain = domain.trim().toLowerCase();

  let dsRes: DohResponse;
  let dnskeyRes: DohResponse;

  try {
    [dsRes, dnskeyRes] = await Promise.all([
      dohQuery(cleanDomain, 'DS', signal),
      dohQuery(cleanDomain, 'DNSKEY', signal),
    ]);
  } catch (err) {
    return {
      status: 'indeterminate',
      domain: cleanDomain,
      adFlag: false,
      dsRecords: [],
      dnskeyRecords: [],
      rrsigCount: 0,
      error: (err as Error).message,
    };
  }

  // Status 2 en resolutores con validación DNSSEC indica SERVFAIL (validación fallida / BOGUS)
  if (dsRes.Status === 2 || dnskeyRes.Status === 2) {
    return {
      status: 'bogus',
      domain: cleanDomain,
      adFlag: false,
      dsRecords: [],
      dnskeyRecords: [],
      rrsigCount: 0,
      error: 'El resolutor DNS devolvió SERVFAIL (cadena de confianza DNSSEC rota o inválida)',
    };
  }

  const dsRecords: DnssecDsRecord[] = (dsRes.Answer ?? [])
    .filter((a) => a.type === 43)
    .map((a) => parseDsRecord(a.data))
    .filter((r): r is DnssecDsRecord => r !== null);

  const dnskeyRecords: DnssecDnskeyRecord[] = (dnskeyRes.Answer ?? [])
    .filter((a) => a.type === 48)
    .map((a) => parseDnskeyRecord(a.data))
    .filter((r): r is DnssecDnskeyRecord => r !== null);

  const rrsigCount = [
    ...(dsRes.Answer ?? []),
    ...(dnskeyRes.Answer ?? []),
  ].filter((a) => a.type === 46).length;

  const adFlag = Boolean(dsRes.AD && dnskeyRes.AD);

  let status: DnssecStatus;
  let error: string | undefined;

  if (adFlag && (dsRecords.length > 0 || dnskeyRecords.length > 0)) {
    status = 'secure';
  } else if (dsRecords.length === 0 && dnskeyRecords.length === 0) {
    status = 'insecure';
  } else if (dsRecords.length > 0 && dnskeyRecords.length === 0) {
    status = 'bogus';
    error = 'Registro DS publicado en zona superior pero no se encontraron registros DNSKEY en la zona';
  } else if (dsRecords.length > 0 && !adFlag) {
    status = 'bogus';
    error = 'Registros DS presentes pero la bandera AD es falsa (validación criptográfica incompleta o no auténtica)';
  } else {
    // dnskeyRecords.length > 0 pero dsRecords.length === 0: zona firmada pero no delegada en padre
    status = 'insecure';
    error = 'Zona con DNSKEY pero sin registro DS delegado en el registrador (isla de seguridad)';
  }

  return {
    status,
    domain: cleanDomain,
    adFlag,
    dsRecords,
    dnskeyRecords,
    rrsigCount,
    error,
  };
}
