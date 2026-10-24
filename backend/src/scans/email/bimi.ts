import { DnsClient } from '../../common/dns/dns-client';

export interface BimiRecord {
  raw: string;
  version: string;
  location: string | null;
  authority: string | null;
  tags: Record<string, string>;
}

export type BimiLookup =
  | { status: 'missing'; queryDomain: string }
  | { status: 'invalid'; queryDomain: string; reason: string; raw?: string }
  | { status: 'valid'; queryDomain: string; record: BimiRecord };

export function isBimiRecord(txt: string): boolean {
  return /^v\s*=\s*BIMI1\s*(;|$)/i.test(txt.trim());
}

export function parseBimiTags(record: string): Record<string, string> {
  const tags: Record<string, string> = {};
  for (const part of record.split(';')) {
    const idx = part.indexOf('=');
    if (idx <= 0) continue;
    tags[part.slice(0, idx).trim().toLowerCase()] = part.slice(idx + 1).trim();
  }
  return tags;
}

export async function lookupBimi(
  domain: string,
  dns: DnsClient,
  selector = 'default',
): Promise<BimiLookup> {
  const queryDomain = `${selector}._bimi.${domain.toLowerCase()}`;
  let records: string[] = [];

  try {
    records = await dns.txt(queryDomain);
  } catch {
    return { status: 'missing', queryDomain };
  }

  const bimiCandidates = records.filter(isBimiRecord);

  if (bimiCandidates.length === 0) {
    return { status: 'missing', queryDomain };
  }

  if (bimiCandidates.length > 1) {
    return {
      status: 'invalid',
      queryDomain,
      reason: 'Múltiples registros BIMI detectados en el mismo selector',
    };
  }

  const raw = bimiCandidates[0];
  const tags = parseBimiTags(raw);

  if (!tags.v || tags.v.toUpperCase() !== 'BIMI1') {
    return {
      status: 'invalid',
      queryDomain,
      reason: 'Versión BIMI no válida o ausente (se requiere v=BIMI1)',
      raw,
    };
  }

  // Tag l= (Location del indicador SVG)
  const location = tags.l || null;
  const authority = tags.a || null;

  if (location && !location.startsWith('https://')) {
    return {
      status: 'invalid',
      queryDomain,
      reason: 'La ubicación del logotipo BIMI (etiqueta l=) debe usar HTTPS seguro',
      raw,
    };
  }

  return {
    status: 'valid',
    queryDomain,
    record: {
      raw,
      version: tags.v,
      location,
      authority,
      tags,
    },
  };
}
