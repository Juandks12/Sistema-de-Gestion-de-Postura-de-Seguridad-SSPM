import { DnsClient } from '../../common/dns/dns-client';

export interface TlsRptRecord {
  version: string;
  rua: string[];
  raw: string;
}

export interface TlsRptResult {
  status: 'valid' | 'missing' | 'invalid';
  record: TlsRptRecord | null;
  error?: string;
}

/**
 * Parsea el registro DNS TXT de TLS Reporting (_smtp._tls.<domain>).
 * Formato RFC 8460: v=TLSRPTv1; rua=mailto:tls-reports@example.com
 */
export function parseTlsRptRecord(raw: string): { record: TlsRptRecord | null; error?: string } {
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
  if (version !== 'TLSRPTv1') {
    return { record: null, error: `Versión TLS-RPT inválida o ausente: "${version ?? 'none'}" (se espera TLSRPTv1)` };
  }

  const ruaRaw = map.get('rua');
  if (!ruaRaw) {
    return { record: null, error: 'Directiva rua (report destination URI) ausente en TLS-RPT' };
  }

  const rua = ruaRaw
    .split(',')
    .map((r) => r.trim())
    .filter(Boolean);

  if (rua.length === 0) {
    return { record: null, error: 'Directiva rua vacía en TLS-RPT' };
  }

  for (const uri of rua) {
    if (!uri.startsWith('mailto:') && !uri.startsWith('https:')) {
      return { record: null, error: `URI inválida en directiva rua: "${uri}". Debe comenzar con mailto: o https:` };
    }
  }

  return {
    record: {
      version,
      rua,
      raw,
    },
  };
}

/**
 * Consulta y valida el registro DNS de TLS-RPT para un dominio.
 */
export async function lookupTlsRpt(domain: string, dns: DnsClient): Promise<TlsRptResult> {
  const tlsRptDomain = `_smtp._tls.${domain}`;
  let txtRecords: string[];

  try {
    txtRecords = await dns.txt(tlsRptDomain);
  } catch (err) {
    return { status: 'invalid', record: null, error: (err as Error).message };
  }

  const rptRecords = txtRecords.filter((t) => t.trim().toLowerCase().startsWith('v=tlsrptv1'));

  if (rptRecords.length === 0) {
    return { status: 'missing', record: null };
  }

  if (rptRecords.length > 1) {
    return {
      status: 'invalid',
      record: null,
      error: `Se encontraron ${rptRecords.length} registros TLS-RPT; solo debe existir uno`,
    };
  }

  const { record, error } = parseTlsRptRecord(rptRecords[0]);
  if (!record || error) {
    return { status: 'invalid', record: null, error };
  }

  return {
    status: 'valid',
    record,
  };
}
