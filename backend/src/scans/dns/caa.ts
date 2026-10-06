import { CaaRecord, DnsClient } from '../../common/dns/dns-client';

export interface CaaLookupResult {
  status: 'valid' | 'missing' | 'invalid';
  domain: string;
  inherited: boolean;
  records: CaaRecord[];
  issue: string[];
  issuewild: string[];
  iodef: string[];
  error?: string;
}

/**
 * Dominios donde buscar registros CAA: el propio dominio y los superiores
 * hasta dos etiquetas (árbol de herencia RFC 8659 Sección 3).
 */
export function caaCandidates(domain: string): string[] {
  const labels = domain.trim().toLowerCase().split('.');
  const out: string[] = [];
  for (let i = 0; labels.length - i >= 2; i += 1) {
    out.push(labels.slice(i).join('.'));
  }
  return out;
}

/**
 * Consulta y audita los registros CAA de un dominio aplicando tree-climbing (RFC 8659).
 */
export async function lookupCaa(domain: string, dns: DnsClient): Promise<CaaLookupResult> {
  const candidates = caaCandidates(domain);

  for (const candidate of candidates) {
    let records: CaaRecord[];
    try {
      records = await dns.caa(candidate);
    } catch (err) {
      return {
        status: 'invalid',
        domain: candidate,
        inherited: candidate !== domain.toLowerCase(),
        records: [],
        issue: [],
        issuewild: [],
        iodef: [],
        error: (err as Error).message,
      };
    }

    if (records.length === 0) continue;

    const inherited = candidate !== domain.toLowerCase();
    const issue: string[] = [];
    const issuewild: string[] = [];
    const iodef: string[] = [];
    let hasInvalidFlag = false;
    let invalidError: string | undefined;

    for (const rec of records) {
      // RFC 8659 Sección 3: bit 0 (0x80 / 128) es el Issuer's Critical Flag.
      // Los bits 1-7 son reservados y deben ser 0.
      if (typeof rec.critical === 'number' && (rec.critical & ~128) !== 0) {
        hasInvalidFlag = true;
        invalidError = `Bandera crítica no reconocida en registro CAA: ${rec.critical}`;
      }

      if (rec.issue !== undefined) {
        issue.push(rec.issue.trim());
      }
      if (rec.issuewild !== undefined) {
        issuewild.push(rec.issuewild.trim());
      }
      if (rec.iodef !== undefined) {
        iodef.push(rec.iodef.trim());
      }
    }

    if (hasInvalidFlag) {
      return {
        status: 'invalid',
        domain: candidate,
        inherited,
        records,
        issue,
        issuewild,
        iodef,
        error: invalidError,
      };
    }

    return {
      status: 'valid',
      domain: candidate,
      inherited,
      records,
      issue,
      issuewild,
      iodef,
    };
  }

  return {
    status: 'missing',
    domain: domain.toLowerCase(),
    inherited: false,
    records: [],
    issue: [],
    issuewild: [],
    iodef: [],
  };
}
