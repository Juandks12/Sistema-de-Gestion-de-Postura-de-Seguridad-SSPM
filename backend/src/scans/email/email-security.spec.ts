import { FindingSeverity } from '@prisma/client';
import { generateKeyPairSync } from 'node:crypto';
import { fakeDns } from '../../common/dns/fake-dns';
import { parseDkimRecord, rsaKeyBits } from './dkim';
import { dmarcCandidates, lookupDmarc } from './dmarc';
import { analyzeEmailSecurity } from './email-security.analyzer';
import { evaluateSpf, parseSpf } from './spf';

const ids = (findings: Array<{ ruleId: string }>) => findings.map((f) => f.ruleId).sort();

function dkimKey(bits: number): string {
  const { publicKey } = generateKeyPairSync('rsa', { modulusLength: bits });
  return publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
}

describe('SPF', () => {
  it('interpreta mecanismos, calificadores y redirect', () => {
    const spf = parseSpf('v=spf1 ip4:192.0.2.0/24 include:_spf.google.com ~all');
    expect(spf.terms.map((t) => `${t.qualifier}${t.mechanism}`)).toEqual(['+ip4', '+include', '~all']);
    expect(parseSpf('v=spf1 redirect=_spf.example.com').redirect).toBe('_spf.example.com');
    expect(parseSpf('v=spf1 include ip9:1.2.3.4 -all').errors).toHaveLength(2);
  });

  it('cuenta las consultas DNS siguiendo los include', async () => {
    const dns = fakeDns({
      txt: {
        'a.example': ['v=spf1 include:b.example include:c.example -all'],
        'b.example': ['v=spf1 a mx -all'],
        'c.example': ['v=spf1 ip4:192.0.2.1 -all'],
      },
    });
    const result = await evaluateSpf('v=spf1 include:a.example mx -all', dns);
    expect(result).toMatchObject({ lookups: 6, errors: [], all: '-' });
  });

  it('detecta más de 10 consultas, include sin SPF y bucles', async () => {
    const includes = Array.from({ length: 11 }, (_, i) => `include:i${i}.example`).join(' ');
    const many = await evaluateSpf(`v=spf1 ${includes} -all`, fakeDns({}));
    expect(many.lookups).toBe(11);
    expect(many.errors.some((e) => e.includes('consultas DNS'))).toBe(true);
    expect(many.errors.some((e) => e.includes('no publica SPF'))).toBe(true);

    const loop = await evaluateSpf('v=spf1 include:x.example -all', fakeDns({ txt: { 'x.example': ['v=spf1 include:x.example -all'] } }));
    expect(loop.errors.some((e) => e.includes('Bucle'))).toBe(true);
  });

  it('toma el "all" del redirect', async () => {
    const dns = fakeDns({ txt: { '_spf.example.com': ['v=spf1 ip4:192.0.2.1 ?all'] } });
    expect((await evaluateSpf('v=spf1 redirect=_spf.example.com', dns)).all).toBe('?');
  });
});

describe('DMARC', () => {
  it('busca en el dominio y en los superiores', () => {
    expect(dmarcCandidates('a.b.example.com')).toEqual(['a.b.example.com', 'b.example.com', 'example.com']);
  });

  it('hereda la política de subdominios (sp) del dominio organizativo', async () => {
    const dns = fakeDns({ txt: { '_dmarc.example.com': ['v=DMARC1; p=reject; sp=quarantine; rua=mailto:d@example.com'] } });
    const result = await lookupDmarc('shop.example.com', dns);
    expect(result).toMatchObject({ status: 'ok', record: { inherited: true, policy: 'reject', subdomainPolicy: 'quarantine', rua: true } });
  });

  it('marca como inválidos varios registros o una política desconocida', async () => {
    expect(await lookupDmarc('example.com', fakeDns({ txt: { '_dmarc.example.com': ['v=DMARC1; p=reject', 'v=DMARC1; p=none'] } }))).toMatchObject({
      status: 'invalid',
    });
    expect(await lookupDmarc('example.com', fakeDns({ txt: { '_dmarc.example.com': ['v=DMARC1; p=bloquear'] } }))).toMatchObject({
      status: 'invalid',
    });
  });
});

describe('DKIM', () => {
  it('lee el registro y la longitud de la clave RSA', () => {
    const key = dkimKey(1024);
    expect(parseDkimRecord(`v=DKIM1; k=rsa; p=${key}`)).toEqual({ keyType: 'rsa', publicKey: key });
    expect(rsaKeyBits(key)).toBe(1024);
    expect(rsaKeyBits('no-es-base64')).toBeNull();
    expect(parseDkimRecord('v=spf1 -all')).toBeNull();
  });
});

describe('analyzeEmailSecurity', () => {
  const key2048 = dkimKey(2048);

  it('un dominio bien configurado no genera hallazgos', async () => {
    const dns = fakeDns({
      mx: { 'example.com': [{ exchange: 'aspmx.l.google.com', priority: 1 }] },
      txt: {
        'example.com': ['google-site-verification=abc', 'v=spf1 include:_spf.google.com -all'],
        '_spf.google.com': ['v=spf1 ip4:192.0.2.0/24 ~all'],
        '_dmarc.example.com': ['v=DMARC1; p=reject; rua=mailto:dmarc@example.com'],
        'google._domainkey.example.com': [`v=DKIM1; k=rsa; p=${key2048}`],
      },
    });
    const { findings, summary } = await analyzeEmailSecurity('example.com', dns);
    expect(findings).toEqual([]);
    expect(summary).toMatchObject({
      receivesMail: true,
      spf: { all: '-all', lookups: 1 },
      dmarc: { status: 'ok', policy: 'reject' },
      dkim: { selectors: [{ selector: 'google', bits: 2048 }] },
    });
  });

  it('un dominio con correo y sin protección genera los hallazgos principales', async () => {
    const dns = fakeDns({ mx: { 'example.com': [{ exchange: 'mail.example.com', priority: 10 }] } });
    const { findings } = await analyzeEmailSecurity('example.com', dns);
    expect(ids(findings)).toEqual(['MAIL-DKIM-NOT-FOUND', 'MAIL-DMARC-MISSING', 'MAIL-SPF-MISSING']);
    expect(findings.find((f) => f.ruleId === 'MAIL-SPF-MISSING')!.severity).toBeUndefined();
  });

  it('detecta +all, p=none sin informes y claves DKIM débiles', async () => {
    const dns = fakeDns({
      mx: { 'example.com': [{ exchange: 'mx.example.com', priority: 10 }] },
      txt: {
        'example.com': ['v=spf1 +all'],
        '_dmarc.example.com': ['v=DMARC1; p=none'],
        'selector1._domainkey.example.com': [`v=DKIM1; p=${dkimKey(1024)}`],
      },
    });
    const { findings } = await analyzeEmailSecurity('example.com', dns);
    expect(ids(findings)).toEqual(['MAIL-DKIM-WEAK-KEY', 'MAIL-DMARC-MONITOR-ONLY', 'MAIL-DMARC-NO-REPORTS', 'MAIL-SPF-PASS-ALL']);
    const weak = findings.find((f) => f.ruleId === 'MAIL-DKIM-WEAK-KEY')!;
    expect(weak).toMatchObject({ severity: FindingSeverity.LOW, location: 'dkim:selector1._domainkey.example.com' });
  });

  it('~all solo se señala si DMARC no rechaza el correo', async () => {
    const base = { mx: { 'example.com': [{ exchange: 'mx.example.com', priority: 10 }] } };
    const txt = (dmarc: string) => ({
      'example.com': ['v=spf1 mx ~all'],
      '_dmarc.example.com': [dmarc],
      'default._domainkey.example.com': [`p=${key2048}`],
    });
    const enforced = await analyzeEmailSecurity('example.com', fakeDns({ ...base, txt: txt('v=DMARC1; p=quarantine; rua=mailto:a@example.com') }));
    expect(ids(enforced.findings)).toEqual([]);
    const partial = await analyzeEmailSecurity('example.com', fakeDns({ ...base, txt: txt('v=DMARC1; p=reject; pct=50; rua=mailto:a@example.com') }));
    expect(ids(partial.findings)).toEqual(['MAIL-DMARC-PARTIAL', 'MAIL-SPF-SOFTFAIL']);
  });

  it('un subdominio sin correo protegido por el DMARC del dominio no genera hallazgos', async () => {
    const dns = fakeDns({ txt: { '_dmarc.example.com': ['v=DMARC1; p=reject; rua=mailto:a@example.com'] } });
    const { findings, summary } = await analyzeEmailSecurity('www.example.com', dns);
    expect(findings).toEqual([]);
    expect(summary.dmarc).toMatchObject({ inherited: true, domain: 'example.com' });
    expect(summary.dkim.checked).toBe(false);
  });

  it('un dominio sin correo ni DMARC debe declarar "v=spf1 -all"', async () => {
    const { findings } = await analyzeEmailSecurity('example.org', fakeDns({ mx: { 'example.org': [{ exchange: '', priority: 0 }] } }));
    expect(ids(findings)).toEqual(['MAIL-DMARC-MISSING', 'MAIL-SPF-MISSING']);
    expect(findings.find((f) => f.ruleId === 'MAIL-SPF-MISSING')).toMatchObject({ severity: FindingSeverity.LOW, cvss: 3.7 });
  });

  it('un fallo del DNS se propaga (no es "sin registro")', async () => {
    await expect(analyzeEmailSecurity('example.com', fakeDns({ mx: { 'example.com': 'SERVFAIL' } }))).rejects.toThrow(/ESERVFAIL/);
  });
});
