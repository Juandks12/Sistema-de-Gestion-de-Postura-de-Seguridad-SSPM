import { FindingSeverity } from '@prisma/client';
import { DnsClient } from '../../common/dns/dns-client';
import { FindingDraft } from '../scanner.interface';
import { findDkimKeys } from './dkim';
import { effectivePolicy, lookupDmarc } from './dmarc';
import { evaluateSpf, isSpfRecord } from './spf';

export interface EmailSecuritySummary {
  receivesMail: boolean;
  mx: string[];
  spf: { record: string | null; records: number; lookups: number | null; all: string | null; errors: string[] };
  dmarc: {
    status: 'missing' | 'invalid' | 'ok';
    record: string | null;
    domain: string | null;
    inherited: boolean;
    policy: string | null;
  };
  dkim: { checked: boolean; selectors: Array<{ selector: string; keyType: string; bits: number | null }> };
}

const QUALIFIER_TEXT: Record<string, string> = { '+': '+all', '-': '-all', '~': '~all', '?': '?all' };

/**
 * Autenticación del correo de un dominio (SPF, DMARC y DKIM) a partir de sus
 * registros DNS públicos. Los dominios que no reciben correo también deben
 * protegerse: si no, se pueden suplantar igualmente.
 */
export async function analyzeEmailSecurity(
  domain: string,
  dns: DnsClient,
): Promise<{ findings: FindingDraft[]; summary: EmailSecuritySummary }> {
  const findings: FindingDraft[] = [];

  const [mxRecords, txt, dmarc] = await Promise.all([dns.mx(domain), dns.txt(domain), lookupDmarc(domain, dns)]);
  const mx = mxRecords
    .filter((r) => r.exchange && r.exchange !== '.')
    .sort((a, b) => a.priority - b.priority)
    .map((r) => r.exchange.toLowerCase());
  const receivesMail = mx.length > 0;

  // ------------------------------------------------------------------ DMARC
  const dmarcLocation = (d: string) => `dmarc:_dmarc.${d}`;
  let enforcing = false;
  if (dmarc.status === 'missing') {
    findings.push({
      ruleId: 'MAIL-DMARC-MISSING',
      location: dmarcLocation(domain),
      evidence: { checked: dmarc.checked, receivesMail },
    });
  } else if (dmarc.status === 'invalid') {
    findings.push({
      ruleId: 'MAIL-DMARC-INVALID',
      location: dmarcLocation(dmarc.domain),
      evidence: { reason: dmarc.reason, records: dmarc.records, inherited: dmarc.inherited },
    });
  } else {
    const r = dmarc.record;
    const policy = effectivePolicy(r);
    enforcing = policy !== 'none' && r.pct === 100;
    const evidence = { record: r.raw, publishedAt: `_dmarc.${r.domain}`, inherited: r.inherited, policy };
    if (policy === 'none') {
      findings.push({ ruleId: 'MAIL-DMARC-MONITOR-ONLY', location: dmarcLocation(r.domain), evidence });
    } else if (r.pct < 100) {
      findings.push({ ruleId: 'MAIL-DMARC-PARTIAL', location: dmarcLocation(r.domain), evidence: { ...evidence, pct: r.pct } });
    }
    // Estas dos se refieren a la configuración del propio registro, no a la heredada.
    if (!r.inherited && r.policy !== 'none' && r.subdomainPolicy === 'none') {
      findings.push({ ruleId: 'MAIL-DMARC-SUBDOMAINS-UNPROTECTED', location: dmarcLocation(r.domain), evidence });
    }
    if (!r.inherited && !r.rua) {
      findings.push({ ruleId: 'MAIL-DMARC-NO-REPORTS', location: dmarcLocation(r.domain), evidence });
    }
  }

  // -------------------------------------------------------------------- SPF
  const spfRecords = txt.filter(isSpfRecord);
  const spfLocation = `spf:${domain}`;
  const spfSummary: EmailSecuritySummary['spf'] = {
    record: spfRecords[0] ?? null,
    records: spfRecords.length,
    lookups: null,
    all: null,
    errors: [],
  };
  if (spfRecords.length === 0) {
    // Un dominio que no envía correo y está cubierto por un DMARC que rechaza ya no es suplantable.
    if (receivesMail || !enforcing) {
      findings.push({
        ruleId: 'MAIL-SPF-MISSING',
        location: spfLocation,
        evidence: { receivesMail },
        ...(receivesMail
          ? {}
          : {
              severity: FindingSeverity.LOW,
              cvss: 3.7,
              title: 'El dominio no envía correo pero no lo declara en SPF',
              recommendation:
                'Publique "v=spf1 -all" para indicar que ningún servidor está autorizado a enviar correo en nombre del dominio.',
            }),
      });
    }
  } else if (spfRecords.length > 1) {
    findings.push({
      ruleId: 'MAIL-SPF-INVALID',
      location: spfLocation,
      title: 'El dominio publica varios registros SPF',
      evidence: { records: spfRecords, reason: 'Solo puede haber un registro v=spf1' },
    });
  } else {
    const evaluation = await evaluateSpf(spfRecords[0], dns);
    spfSummary.lookups = evaluation.lookups;
    spfSummary.all = evaluation.all ? QUALIFIER_TEXT[evaluation.all] : null;
    spfSummary.errors = evaluation.errors;
    const evidence = { record: spfRecords[0], lookups: evaluation.lookups, all: spfSummary.all };
    if (evaluation.errors.length > 0) {
      findings.push({ ruleId: 'MAIL-SPF-INVALID', location: spfLocation, evidence: { ...evidence, errors: evaluation.errors } });
    }
    if (evaluation.all === '+') {
      findings.push({ ruleId: 'MAIL-SPF-PASS-ALL', location: spfLocation, evidence });
    } else if (evaluation.all === '?' || evaluation.all === null) {
      findings.push({ ruleId: 'MAIL-SPF-NEUTRAL', location: spfLocation, evidence });
    } else if (evaluation.all === '~' && !enforcing) {
      findings.push({ ruleId: 'MAIL-SPF-SOFTFAIL', location: spfLocation, evidence });
    }
  }

  // ------------------------------------------------------------------- DKIM
  const dkim = receivesMail ? await findDkimKeys(domain, dns) : [];
  if (receivesMail && dkim.length === 0) {
    findings.push({ ruleId: 'MAIL-DKIM-NOT-FOUND', location: `dkim:${domain}`, evidence: { mx } });
  }
  for (const key of dkim) {
    if (key.bits === null || key.bits >= 2048) continue;
    findings.push({
      ruleId: 'MAIL-DKIM-WEAK-KEY',
      location: `dkim:${key.selector}._domainkey.${domain}`,
      title: `Clave DKIM de ${key.bits} bits en el selector ${key.selector}`,
      evidence: { selector: key.selector, bits: key.bits },
      ...(key.bits >= 1024 ? { severity: FindingSeverity.LOW, cvss: 3.7 } : {}),
    });
  }

  return {
    findings,
    summary: {
      receivesMail,
      mx,
      spf: spfSummary,
      dmarc:
        dmarc.status === 'ok'
          ? {
              status: 'ok',
              record: dmarc.record.raw,
              domain: dmarc.record.domain,
              inherited: dmarc.record.inherited,
              policy: effectivePolicy(dmarc.record),
            }
          : dmarc.status === 'invalid'
            ? { status: 'invalid', record: dmarc.records[0] ?? null, domain: dmarc.domain, inherited: dmarc.inherited, policy: null }
            : { status: 'missing', record: null, domain: null, inherited: false, policy: null },
      dkim: { checked: receivesMail, selectors: dkim },
    },
  };
}
