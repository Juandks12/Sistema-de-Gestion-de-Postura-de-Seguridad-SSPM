import { DnsClient } from '../../common/dns/dns-client';
import { FindingDraft } from '../scanner.interface';
import { lookupCaa } from './caa';
import { DohQueryFn, DnssecStatus, lookupDnssec } from './dnssec';

export interface DnsSecuritySummary {
  caa: {
    status: 'valid' | 'missing' | 'invalid';
    domain: string;
    inherited: boolean;
    issue: string[];
    issuewild: string[];
    iodef: string[];
    error?: string;
  };
  dnssec: {
    status: DnssecStatus;
    domain: string;
    adFlag: boolean;
    dsCount: number;
    dnskeyCount: number;
    rrsigCount: number;
    error?: string;
  };
  wildcard?: {
    enabled: boolean;
    probeHost: string;
    addresses: string[];
  };
}

export async function analyzeDnsSecurity(
  domain: string,
  dns: DnsClient,
  dohQuery?: DohQueryFn,
  signal?: AbortSignal,
): Promise<{ findings: FindingDraft[]; summary: DnsSecuritySummary }> {
  const findings: FindingDraft[] = [];
  const probeHost = `_sspm-wildcard-probe.${domain}`;

  const [caa, dnssec, wildcardAddresses] = await Promise.all([
    lookupCaa(domain, dns),
    lookupDnssec(domain, dohQuery, signal),
    dns.addresses(probeHost).catch(() => [] as string[]),
  ]);

  // ----------------------------------------------------------------- Wildcard DNS
  if (wildcardAddresses.length > 0) {
    findings.push({
      ruleId: 'DNS-WILDCARD-ENABLED',
      location: `dns:*.${domain}`,
      title: `Resolución DNS Wildcard (*.${domain}) activa`,
      evidence: {
        domain,
        probeHost,
        resolvedAddresses: wildcardAddresses.slice(0, 10),
      },
    });
  }

  // --------------------------------------------------------------------- CAA
  if (caa.status === 'missing') {
    findings.push({
      ruleId: 'DNS-NO-CAA',
      location: `caa:${domain}`,
      title: 'Registro DNS CAA no configurado (RFC 8659)',
      evidence: { domain, status: 'missing' },
    });
  } else if (caa.status === 'invalid') {
    findings.push({
      ruleId: 'DNS-CAA-INVALID',
      location: `caa:${domain}`,
      title: 'Registro DNS CAA con sintaxis inválida o flags no reconocidos',
      evidence: { domain, status: 'invalid', error: caa.error, records: caa.records },
    });
  }

  // ------------------------------------------------------------------ DNSSEC
  if (dnssec.status === 'insecure') {
    findings.push({
      ruleId: 'DNS-NO-DNSSEC',
      location: `dnssec:${domain}`,
      title: 'DNSSEC no habilitado en el dominio (RFC 4033)',
      evidence: { domain, status: 'insecure', adFlag: dnssec.adFlag },
    });
  } else if (dnssec.status === 'bogus') {
    findings.push({
      ruleId: 'DNS-DNSSEC-BOGUS',
      location: `dnssec:${domain}`,
      title: 'Cadena de confianza DNSSEC rota o inválida',
      evidence: { domain, status: 'bogus', adFlag: dnssec.adFlag, error: dnssec.error },
    });
  }

  return {
    findings,
    summary: {
      caa: {
        status: caa.status,
        domain: caa.domain,
        inherited: caa.inherited,
        issue: caa.issue,
        issuewild: caa.issuewild,
        iodef: caa.iodef,
        error: caa.error,
      },
      dnssec: {
        status: dnssec.status,
        domain: dnssec.domain,
        adFlag: dnssec.adFlag,
        dsCount: dnssec.dsRecords.length,
        dnskeyCount: dnssec.dnskeyRecords.length,
        rrsigCount: dnssec.rrsigCount,
        error: dnssec.error,
      },
      wildcard: {
        enabled: wildcardAddresses.length > 0,
        probeHost,
        addresses: wildcardAddresses.slice(0, 10),
      },
    },
  };
}
