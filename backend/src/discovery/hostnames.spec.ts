import { subdomainsFromCt } from './hostnames';

describe('subdomainsFromCt', () => {
  it('normaliza, deduplica y filtra los nombres de los certificados', () => {
    const { hosts, truncated } = subdomainsFromCt(
      [
        { name: 'www.example.com\nexample.com', notBefore: '2026-01-01T00:00:00' },
        { name: '*.dev.example.com', notBefore: '2026-03-01T00:00:00' },
        { name: 'dev.example.com', notBefore: '2025-12-01T00:00:00' },
        { name: 'WWW.Example.com.', notBefore: '2026-02-01T00:00:00' },
        { name: 'admin@example.com', notBefore: null },
        { name: 'notexample.com', notBefore: null },
        { name: 'evil-example.com', notBefore: null },
        { name: 'bad_host..example.com', notBefore: null },
      ],
      'example.com',
      100,
    );
    expect(truncated).toBe(false);
    expect(hosts).toEqual([
      { hostname: 'dev.example.com', wildcard: true, lastCertificateAt: new Date('2026-03-01T00:00:00') },
      { hostname: 'www.example.com', wildcard: false, lastCertificateAt: new Date('2026-02-01T00:00:00') },
    ]);
  });

  it('recorta al máximo configurado', () => {
    const names = Array.from({ length: 5 }, (_, i) => ({ name: `h${i}.example.com`, notBefore: null }));
    const { hosts, truncated } = subdomainsFromCt(names, 'example.com', 3);
    expect(hosts.map((h) => h.hostname)).toEqual(['h0.example.com', 'h1.example.com', 'h2.example.com']);
    expect(truncated).toBe(true);
  });
});
