import { AssetType } from '@prisma/client';
import { fakeDns } from '../../common/dns/fake-dns';
import { ScanContext } from '../scanner.interface';
import { EmailSecurityScanner } from './email-security.scanner';

describe('EmailSecurityScanner', () => {
  it('combina resultados de seguridad de correo y seguridad DNS (CAA/DNSSEC)', async () => {
    const dns = fakeDns({
      mx: { 'example.com': [{ exchange: 'mail.example.com', priority: 10 }] },
      caa: {
        'example.com': [{ critical: 0, issue: 'letsencrypt.org' }],
      },
    });

    const fakeDoh = async () => ({
      Status: 0,
      AD: false,
      Answer: [],
    });

    const scanner = new EmailSecurityScanner(dns, fakeDoh);

    const ctx: ScanContext = {
      scanId: 'scan-1',
      organizationId: 'org-1',
      asset: {
        id: 'asset-1',
        type: AssetType.DOMAIN,
        value: 'example.com',
        organizationId: 'org-1',
        name: 'Example Domain',
        description: null,
        criticality: 'MEDIUM',
        tags: [],
        isActive: true,
        authorizationConfirmed: true,
        authorizedAt: new Date(),
        createdById: null,
        lastScannedAt: null,
        lastScheduledScanAt: null,
        verifiedAt: new Date(),
        verificationMethod: 'DNS_TXT',
        verificationScope: 'example.com',
        verificationCheckedAt: new Date(),
        verificationError: null,
        createdAt: new Date(),
        updatedAt: new Date(),
      },
      target: null,
      allowPrivate: false,
      openPorts: [],
      signal: new AbortController().signal,
      timeoutMs: 5000,
    };

    const outcome = await scanner.run(ctx);

    expect(outcome.summary).toHaveProperty('caa');
    expect(outcome.summary).toHaveProperty('dnssec');
    expect(outcome.summary).toHaveProperty('spf');
    expect(outcome.summary).toHaveProperty('dmarc');
    expect(outcome.findings.length).toBeGreaterThan(0);
    // Debe incluir hallazgos de DNS como DNS-NO-DNSSEC si no hay DNSSEC
    expect(outcome.findings.some((f) => f.ruleId === 'DNS-NO-DNSSEC')).toBe(true);
  });
});
