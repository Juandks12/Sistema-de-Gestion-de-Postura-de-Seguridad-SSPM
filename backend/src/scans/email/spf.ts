import { DnsClient, DnsLookupError } from '../../common/dns/dns-client';

/** Máximo de consultas DNS que permite una evaluación SPF (RFC 7208, 4.6.4). */
export const SPF_MAX_LOOKUPS = 10;

export type SpfQualifier = '+' | '-' | '~' | '?';

export interface SpfTerm {
  qualifier: SpfQualifier;
  mechanism: string;
  value: string | null;
}

export interface ParsedSpf {
  terms: SpfTerm[];
  redirect: string | null;
  errors: string[];
}

const MECHANISMS = new Set(['all', 'include', 'a', 'mx', 'ptr', 'ip4', 'ip6', 'exists']);
/** Mecanismos que consumen una consulta DNS. */
const LOOKUP_MECHANISMS = new Set(['include', 'a', 'mx', 'ptr', 'exists']);

export function isSpfRecord(txt: string): boolean {
  return /^v=spf1(\s|$)/i.test(txt.trim());
}

export function parseSpf(record: string): ParsedSpf {
  const terms: SpfTerm[] = [];
  const errors: string[] = [];
  let redirect: string | null = null;
  for (const token of record.trim().split(/\s+/).slice(1)) {
    const modifier = /^([a-z][a-z0-9_.-]*)=(.*)$/i.exec(token);
    if (modifier) {
      if (modifier[1].toLowerCase() === 'redirect') redirect = modifier[2].toLowerCase();
      continue;
    }
    const m = /^([+\-~?]?)([a-z0-9]+)(?:[:/](.*))?$/i.exec(token);
    const mechanism = m?.[2].toLowerCase();
    if (!m || !mechanism || !MECHANISMS.has(mechanism)) {
      errors.push(`Mecanismo no válido: ${token}`);
      continue;
    }
    const value = token.includes(':') ? token.slice(token.indexOf(':') + 1) : null;
    if ((mechanism === 'include' || mechanism === 'exists') && !value) {
      errors.push(`${mechanism} sin dominio`);
      continue;
    }
    terms.push({ qualifier: ((m[1] || '+') as SpfQualifier), mechanism, value });
  }
  return { terms, redirect, errors };
}

export interface SpfEvaluation {
  lookups: number;
  errors: string[];
  /** Calificador del "all" efectivo (propio o del redirect), o null si no hay. */
  all: SpfQualifier | null;
}

/**
 * Cuenta las consultas DNS de un SPF siguiendo include y redirect (hasta
 * pasar del límite) y detecta los errores que invalidan la política.
 */
export async function evaluateSpf(record: string, dns: DnsClient): Promise<SpfEvaluation> {
  const state = { lookups: 0, errors: [] as string[] };
  const visited = new Set<string>();

  const walk = async (spf: ParsedSpf, depth: number): Promise<SpfQualifier | null> => {
    state.errors.push(...spf.errors);
    for (const term of spf.terms) {
      if (!LOOKUP_MECHANISMS.has(term.mechanism)) continue;
      state.lookups += 1;
      if (term.mechanism === 'include' && term.value && state.lookups <= SPF_MAX_LOOKUPS && depth < 10) {
        await follow(term.value.toLowerCase(), depth + 1, 'include');
      }
    }
    const all = spf.terms.find((t) => t.mechanism === 'all');
    if (all) return all.qualifier;
    if (spf.redirect) {
      state.lookups += 1;
      if (state.lookups <= SPF_MAX_LOOKUPS && depth < 10) return follow(spf.redirect, depth + 1, 'redirect');
    }
    return null;
  };

  const follow = async (domain: string, depth: number, via: string): Promise<SpfQualifier | null> => {
    if (visited.has(domain)) {
      state.errors.push(`Bucle de ${via} en ${domain}`);
      return null;
    }
    visited.add(domain);
    let records: string[];
    try {
      records = (await dns.txt(domain)).filter(isSpfRecord);
    } catch (err) {
      if (err instanceof DnsLookupError) return null; // error temporal: no invalida la política
      throw err;
    }
    if (records.length !== 1) {
      state.errors.push(records.length === 0 ? `${via}:${domain} no publica SPF` : `${via}:${domain} tiene varios SPF`);
      return null;
    }
    return walk(parseSpf(records[0]), depth);
  };

  const all = await walk(parseSpf(record), 0);
  if (state.lookups > SPF_MAX_LOOKUPS) {
    state.errors.push(`Requiere ${state.lookups} consultas DNS (máximo ${SPF_MAX_LOOKUPS})`);
  }
  return { lookups: state.lookups, errors: state.errors, all };
}
