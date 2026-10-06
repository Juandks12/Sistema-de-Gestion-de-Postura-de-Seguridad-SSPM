import { fakeDns } from '../../common/dns/fake-dns';
import { analyzeDnsSecurity } from './dns-security.analyzer';
import { DohQueryFn } from './dnssec';

describe('analyzeDnsSecurity', () => {
  it('un dominio con CAA y DNSSEC configurados no genera hallazgos', async () => {
    const dns = fakeDns({
      caa: {
        'example.com': [
          { critical: 0, issue: 'letsencrypt.org' },
          { critical: 0, iodef: 'mailto:security@example.com' },
        ],
      },
    });

    const fakeDoh: DohQueryFn = async (_name, type) => {
      if (type === 'DS') {
        return {
          Status: 0,
          AD: true,
          Answer: [{ name: 'example.com', type: 43, TTL: 3600, data: '2371 13 2 32996839A6D808AF' }],
        };
      }
      return {
        Status: 0,
        AD: true,
        Answer: [{ name: 'example.com', type: 48, TTL: 3600, data: '257 3 13 pubkey123' }],
      };
    };

    const { findings, summary } = await analyzeDnsSecurity('example.com', dns, fakeDoh);
    expect(findings).toEqual([]);
    expect(summary.caa.status).toBe('valid');
    expect(summary.caa.issue).toEqual(['letsencrypt.org']);
    expect(summary.dnssec.status).toBe('secure');
    expect(summary.dnssec.adFlag).toBe(true);
  });

  it('un dominio sin CAA ni DNSSEC genera DNS-NO-CAA y DNS-NO-DNSSEC', async () => {
    const dns = fakeDns({});
    const fakeDoh: DohQueryFn = async () => ({
      Status: 0,
      AD: false,
      Answer: [],
    });

    const { findings, summary } = await analyzeDnsSecurity('example.com', dns, fakeDoh);
    const ruleIds = findings.map((f) => f.ruleId).sort();
    expect(ruleIds).toEqual(['DNS-NO-CAA', 'DNS-NO-DNSSEC']);
    expect(summary.caa.status).toBe('missing');
    expect(summary.dnssec.status).toBe('insecure');
  });

  it('detecta registros CAA inválidos y DNSSEC roto (bogus)', async () => {
    const dns = fakeDns({
      caa: {
        'example.com': [{ critical: 64, issue: 'letsencrypt.org' }], // critical flag inválida
      },
    });
    const fakeDoh: DohQueryFn = async () => ({
      Status: 2, // SERVFAIL
      AD: false,
      Answer: [],
    });

    const { findings, summary } = await analyzeDnsSecurity('example.com', dns, fakeDoh);
    const ruleIds = findings.map((f) => f.ruleId).sort();
    expect(ruleIds).toEqual(['DNS-CAA-INVALID', 'DNS-DNSSEC-BOGUS']);
    expect(summary.caa.status).toBe('invalid');
    expect(summary.dnssec.status).toBe('bogus');
  });
});
