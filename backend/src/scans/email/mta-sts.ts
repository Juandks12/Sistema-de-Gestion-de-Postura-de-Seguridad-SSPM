import { DnsClient } from '../../common/dns/dns-client';

export type MtaStsMode = 'enforce' | 'testing' | 'none';

export interface MtaStsPolicy {
  version: string;
  mode: MtaStsMode;
  mx: string[];
  maxAge: number;
  raw: string;
}

export interface MtaStsDnsRecord {
  version: string;
  id: string;
  raw: string;
}

export interface MtaStsResult {
  status: 'valid' | 'missing' | 'invalid';
  dnsRecord: MtaStsDnsRecord | null;
  policy: MtaStsPolicy | null;
  error?: string;
}

const MAX_POLICY_BYTES = 64 * 1024;
const HTTP_TIMEOUT_MS = 5000;

export type FetchPolicyFn = (url: string, signal?: AbortSignal) => Promise<{ status: number; text: string; ok: boolean }>;

export const defaultFetchPolicy: FetchPolicyFn = async (url: string, signal?: AbortSignal) => {
  const abortSignals = [AbortSignal.timeout(HTTP_TIMEOUT_MS)];
  if (signal) abortSignals.push(signal);

  const res = await fetch(url, {
    headers: {
      accept: 'text/plain',
      'user-agent': 'SSPM-SaaS-Lite (MTA-STS validator; RFC 8461)',
    },
    signal: AbortSignal.any(abortSignals),
  });

  if (!res.ok) {
    return { status: res.status, text: '', ok: false };
  }

  const text = await res.text();
  if (text.length > MAX_POLICY_BYTES) {
    throw new Error('Archivo de política supera el tamaño máximo permitido (64 KB)');
  }

  return { status: res.status, text, ok: true };
};

/**
 * Parsea el registro DNS TXT de MTA-STS (_mta-sts.<domain>).
 * Formato RFC 8461: v=STSv1; id=2026093001
 */
export function parseMtaStsDnsRecord(raw: string): { record: MtaStsDnsRecord | null; error?: string } {
  const parts = raw.split(';').map((p) => p.trim()).filter(Boolean);
  const map = new Map<string, string>();

  for (const part of parts) {
    const eqIdx = part.indexOf('=');
    if (eqIdx === -1) continue;
    const key = part.slice(0, eqIdx).trim().toLowerCase();
    const val = part.slice(eqIdx + 1).trim();
    map.set(key, val);
  }

  const version = map.get('v');
  if (version !== 'STSv1') {
    return { record: null, error: `Versión MTA-STS inválida o ausente: "${version ?? 'none'}" (se espera STSv1)` };
  }

  const id = map.get('id');
  if (!id || !/^[a-zA-Z0-9]{1,32}$/.test(id)) {
    return { record: null, error: `Identificador de política "id" ausente o inválido: "${id ?? ''}"` };
  }

  return {
    record: {
      version,
      id,
      raw,
    },
  };
}

/**
 * Parsea y valida el contenido del archivo de política /.well-known/mta-sts.txt (RFC 8461 Sección 3.2).
 */
export function parseMtaStsPolicy(text: string): { policy: MtaStsPolicy | null; error?: string } {
  const lines = text.split(/\r?\n/).map((l) => l.trim()).filter((l) => l.length > 0 && !l.startsWith('#'));

  let version: string | null = null;
  let mode: MtaStsMode | null = null;
  let maxAge: number | null = null;
  const mx: string[] = [];

  for (const line of lines) {
    const colonIdx = line.indexOf(':');
    if (colonIdx === -1) continue;
    const key = line.slice(0, colonIdx).trim().toLowerCase();
    const val = line.slice(colonIdx + 1).trim();

    if (key === 'version') {
      version = val;
    } else if (key === 'mode') {
      if (val === 'enforce' || val === 'testing' || val === 'none') {
        mode = val;
      }
    } else if (key === 'max_age') {
      const parsed = parseInt(val, 10);
      if (!Number.isNaN(parsed) && parsed >= 0) {
        maxAge = parsed;
      }
    } else if (key === 'mx') {
      if (val) mx.push(val.toLowerCase());
    }
  }

  if (version !== 'STSv1') {
    return { policy: null, error: 'La directiva version debe ser STSv1' };
  }

  if (!mode) {
    return { policy: null, error: 'Directiva mode ausente o no permitida (debe ser enforce, testing o none)' };
  }

  if (maxAge === null) {
    return { policy: null, error: 'Directiva max_age ausente o inválida' };
  }

  if ((mode === 'enforce' || mode === 'testing') && mx.length === 0) {
    return { policy: null, error: `Modo "${mode}" requiere al menos una directiva mx` };
  }

  return {
    policy: {
      version,
      mode,
      maxAge,
      mx,
      raw: text,
    },
  };
}

/**
 * Consulta y valida la configuración completa de MTA-STS para un dominio.
 */
export async function lookupMtaSts(
  domain: string,
  dns: DnsClient,
  fetchPolicy: FetchPolicyFn = defaultFetchPolicy,
  signal?: AbortSignal,
): Promise<MtaStsResult> {
  const mtaStsDomain = `_mta-sts.${domain}`;
  let txtRecords: string[];

  try {
    txtRecords = await dns.txt(mtaStsDomain);
  } catch (err) {
    return { status: 'invalid', dnsRecord: null, policy: null, error: (err as Error).message };
  }

  const stsRecords = txtRecords.filter((t) => t.trim().toLowerCase().startsWith('v=stsv1'));

  if (stsRecords.length === 0) {
    return { status: 'missing', dnsRecord: null, policy: null };
  }

  if (stsRecords.length > 1) {
    return {
      status: 'invalid',
      dnsRecord: null,
      policy: null,
      error: `Se encontraron ${stsRecords.length} registros MTA-STS; solo debe haber uno`,
    };
  }

  const { record: dnsRecord, error: dnsError } = parseMtaStsDnsRecord(stsRecords[0]);
  if (!dnsRecord || dnsError) {
    return { status: 'invalid', dnsRecord: null, policy: null, error: dnsError };
  }

  // Descargar archivo de política vía HTTPS
  const policyUrl = `https://mta-sts.${domain}/.well-known/mta-sts.txt`;
  let policyText: string;

  try {
    const res = await fetchPolicy(policyUrl, signal);
    if (!res.ok) {
      return {
        status: 'invalid',
        dnsRecord,
        policy: null,
        error: `Servidor HTTPS respondió status ${res.status} al consultar ${policyUrl}`,
      };
    }
    policyText = res.text;
  } catch (err) {
    return {
      status: 'invalid',
      dnsRecord,
      policy: null,
      error: `No se pudo obtener el archivo de política HTTPS: ${(err as Error).message}`,
    };
  }

  const { policy, error: policyError } = parseMtaStsPolicy(policyText);
  if (!policy || policyError) {
    return { status: 'invalid', dnsRecord, policy: null, error: policyError };
  }

  return {
    status: 'valid',
    dnsRecord,
    policy,
  };
}
