import { fingerprintTechnologies } from './tech-fingerprint';

describe('tech-fingerprint', () => {
  it('detecta Nginx y genera alerta EOL si la versión es muy antigua', () => {
    const res = fingerprintTechnologies({
      finalUrl: 'https://example.com/',
      status: 200,
      headers: {
        server: 'nginx/1.14.0',
      },
    });

    const nginx = res.technologies.find((t) => t.name === 'Nginx');
    expect(nginx).toBeDefined();
    expect(nginx?.version).toBe('1.14.0');
    expect(nginx?.eol).toBe(true);
    expect(res.findings.some((f) => f.ruleId === 'HDR-EOL-TECH')).toBe(true);
  });

  it('detecta Apache moderno sin marcar EOL', () => {
    const res = fingerprintTechnologies({
      finalUrl: 'https://example.com/',
      status: 200,
      headers: {
        server: 'Apache/2.4.58 (Ubuntu)',
      },
    });

    const apache = res.technologies.find((t) => t.name === 'Apache');
    expect(apache).toBeDefined();
    expect(apache?.version).toBe('2.4.58');
    expect(apache?.eol).toBeUndefined();
    expect(res.findings.length).toBe(0);
  });

  it('detecta PHP 7.4 en EOL a través de X-Powered-By y Set-Cookie', () => {
    const res = fingerprintTechnologies({
      finalUrl: 'https://example.com/',
      status: 200,
      headers: {
        'x-powered-by': 'PHP/7.4.33',
        'set-cookie': 'PHPSESSID=abcdef123456; path=/',
      },
    });

    const php = res.technologies.find((t) => t.name === 'PHP');
    expect(php).toBeDefined();
    expect(php?.version).toBe('7.4.33');
    expect(php?.eol).toBe(true);
    expect(res.findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          ruleId: 'HDR-EOL-TECH',
          evidence: expect.objectContaining({ technology: 'PHP', version: '7.4.33' }),
        }),
      ]),
    );
  });

  it('detecta WordPress con versión extraída de meta generator', () => {
    const html = `
      <!DOCTYPE html>
      <html>
        <head>
          <meta name="generator" content="WordPress 5.8.1" />
          <link rel="stylesheet" href="/wp-content/themes/twentytwentyone/style.css" />
        </head>
        <body>Contenido</body>
      </html>
    `;

    const res = fingerprintTechnologies({
      finalUrl: 'https://blog.example.com/',
      status: 200,
      headers: {},
      bodyText: html,
    });

    const wp = res.technologies.find((t) => t.name === 'WordPress');
    expect(wp).toBeDefined();
    expect(wp?.version).toBe('5.8.1');
    expect(wp?.eol).toBe(true);
    // Además infiere PHP
    expect(res.technologies.some((t) => t.name === 'PHP')).toBe(true);
  });

  it('detecta Next.js y React mediante cabeceras y scripts', () => {
    const res = fingerprintTechnologies({
      finalUrl: 'https://app.example.com/',
      status: 200,
      headers: {
        'x-powered-by': 'Next.js',
      },
      bodyText: '<div id="__next"><script src="/_next/static/chunks/main.js"></script></div>',
    });

    expect(res.technologies.some((t) => t.name === 'Next.js')).toBe(true);
    expect(res.technologies.some((t) => t.name === 'React')).toBe(true);
  });

  it('detecta jQuery antiguo en el cuerpo HTML y marca EOL', () => {
    const res = fingerprintTechnologies({
      finalUrl: 'https://example.com/',
      status: 200,
      headers: {},
      bodyText: '<script src="/static/js/jquery-1.12.4.min.js"></script>',
    });

    const jq = res.technologies.find((t) => t.name === 'jQuery');
    expect(jq).toBeDefined();
    expect(jq?.version).toBe('1.12.4');
    expect(jq?.eol).toBe(true);
  });
});
