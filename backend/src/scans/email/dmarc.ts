import { DnsClient } from '../../common/dns/dns-client';

export type DmarcPolicy = 'none' | 'quarantine' | 'reject';

export interface DmarcRecord {
  raw: string;
  /** Dominio donde se publica (el propio o uno superior). */
  domain: string;
  inherited: boolean;
  tags: Record<string, string>;
  policy: DmarcPolicy | null;
  subdomainPolicy: DmarcPolicy | null;
  pct: number;
  rua: boolean;
}

export type DmarcLookup =
  | { status: 'missing'; checked: string[] }
  | { status: 'invalid'; domain: string; inherited: boolean; reason: string; records: string[] }
  | { status: 'ok'; record: DmarcRecord };

const POLICIES = new Set(['none', 'quarantine', 'reject']);

export function isDmarcRecord(txt: string): boolean {
  return /^v\s*=\s*DMARC1\s*(;|$)/i.test(txt.trim());
}

export function parseDmarcTags(record: string): Record<string, string> {
  const tags: Record<string, string> = {};
  for (const part of record.split(';')) {
    const i = part.indexOf('=');
    if (i <= 0) continue;
    tags[part.slice(0, i).trim().toLowerCase()] = part.slice(i + 1).trim();
  }
  return tags;
}

function policyOf(value: string | undefined): DmarcPolicy | null {
  const v = value?.toLowerCase();
  return v && POLICIES.has(v) ? (v as DmarcPolicy) : null;
}

/** Dominios donde buscar DMARC: el propio y los superiores hasta dos etiquetas. */
export function dmarcCandidates(domain: string): string[] {
  const labels = domain.split('.');
  const out: string[] = [];
  for (let i = 0; labels.length - i >= 2; i += 1) out.push(labels.slice(i).join('.'));
  return out;
}

/**
 * Política DMARC aplicable al dominio: la suya o, si no tiene, la del dominio
 * organizativo (RFC 7489, 6.6.3), donde se aplica `sp` si existe.
 */
export async function lookupDmarc(domain: string, dns: DnsClient): Promise<DmarcLookup> {
  const candidates = dmarcCandidates(domain);
  for (const candidate of candidates) {
    const records = (await dns.txt(`_dmarc.${candidate}`)).filter(isDmarcRecord);
    if (records.length === 0) continue;
    const inherited = candidate !== domain;
    if (records.length > 1) {
      return { status: 'invalid', domain: candidate, inherited, reason: 'Hay varios registros DMARC', records };
    }
    const tags = parseDmarcTags(records[0]);
    const policy = policyOf(tags.p);
    if (!policy) {
      return { status: 'invalid', domain: candidate, inherited, reason: 'Falta una política p= válida', records };
    }
    const pct = tags.pct !== undefined && /^\d{1,3}$/.test(tags.pct) ? Math.min(100, Number(tags.pct)) : 100;
    return {
      status: 'ok',
      record: {
        raw: records[0],
        domain: candidate,
        inherited,
        tags,
        policy,
        subdomainPolicy: policyOf(tags.sp),
        pct,
        rua: !!tags.rua && /mailto:/i.test(tags.rua),
      },
    };
  }
  return { status: 'missing', checked: candidates.map((c) => `_dmarc.${c}`) };
}

/** Política que se aplica al propio dominio (la de subdominios si se hereda). */
export function effectivePolicy(record: DmarcRecord): DmarcPolicy {
  return (record.inherited ? (record.subdomainPolicy ?? record.policy) : record.policy) ?? 'none';
}
