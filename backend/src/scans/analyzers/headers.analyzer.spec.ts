import { analyzeHeaders } from './headers.analyzer';

const secure = {
  'strict-transport-security': 'max-age=31536000; includeSubDomains',
  'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'strict-origin-when-cross-origin',
  'permissions-policy': 'camera=(), geolocation=()',
};

const ids = (input: Parameters<typeof analyzeHeaders>[0]) => analyzeHeaders(input).map((f) => f.ruleId);

describe('analyzeHeaders', () => {
  it('no reporta nada en una respuesta bien configurada', () => {
    expect(ids({ finalUrl: 'https://example.org/', status: 200, headers: secure })).toEqual([]);
  });

  it('reporta todas las cabeceras ausentes en HTTPS', () => {
    const result = ids({ finalUrl: 'https://example.org/', status: 200, headers: {} });
    expect(result).toEqual(
      expect.arrayContaining([
        'HDR-HSTS-MISSING',
        'HDR-CSP-MISSING',
        'HDR-XFO-MISSING',
        'HDR-XCTO-MISSING',
        'HDR-REFERRER-MISSING',
        'HDR-PERMISSIONS-MISSING',
      ]),
    );
  });

  it('no exige HSTS en HTTP pero sí detecta la falta de redirección a HTTPS', () => {
    const result = ids({ finalUrl: 'http://example.org/', status: 200, headers: {}, httpsAvailable: true });
    expect(result).not.toContain('HDR-HSTS-MISSING');
    expect(result).toContain('HDR-HTTP-NO-REDIRECT');
    expect(ids({ finalUrl: 'http://example.org/', status: 200, headers: {}, httpsAvailable: false })).not.toContain(
      'HDR-HTTP-NO-REDIRECT',
    );
  });

  it('detecta HSTS corto y CSP permisiva', () => {
    const result = ids({
      finalUrl: 'https://example.org/',
      status: 200,
      headers: {
        ...secure,
        'strict-transport-security': 'max-age=3600',
        'content-security-policy': "default-src * 'unsafe-inline'; frame-ancestors 'self'",
      },
    });
    expect(result).toContain('HDR-HSTS-SHORT');
    expect(result).toContain('HDR-CSP-UNSAFE');
    expect(result).not.toContain('HDR-XFO-MISSING');
  });

  it('acepta X-Frame-Options como alternativa a frame-ancestors', () => {
    const result = ids({
      finalUrl: 'https://example.org/',
      status: 200,
      headers: { ...secure, 'content-security-policy': "default-src 'self'", 'x-frame-options': 'DENY' },
    });
    expect(result).not.toContain('HDR-XFO-MISSING');
  });

  it('detecta divulgación de versiones y tecnología', () => {
    const result = ids({
      finalUrl: 'https://example.org/',
      status: 200,
      headers: { ...secure, server: 'Apache/2.4.41 (Ubuntu)', 'x-powered-by': 'PHP/7.4' },
    });
    expect(result).toEqual(expect.arrayContaining(['HDR-SERVER-VERSION', 'HDR-POWERED-BY']));
    expect(ids({ finalUrl: 'https://example.org/', status: 200, headers: { ...secure, server: 'nginx' } })).not.toContain(
      'HDR-SERVER-VERSION',
    );
  });

  it('evalúa los atributos de las cookies', () => {
    const findings = analyzeHeaders({
      finalUrl: 'https://example.org/',
      status: 200,
      headers: { ...secure, 'set-cookie': ['sessionid=abc; Path=/', 'theme=dark; Secure', 'PHPSESSID=x; Secure; HttpOnly'] },
    });
    const byRule = findings.map((f) => `${f.ruleId}:${f.location}`);
    expect(byRule).toContain('HDR-COOKIE-INSECURE:https://example.org/#cookie:sessionid');
    expect(byRule).toContain('HDR-COOKIE-NO-HTTPONLY:https://example.org/#cookie:sessionid');
    expect(byRule).not.toContain('HDR-COOKIE-INSECURE:https://example.org/#cookie:theme');
    expect(byRule.filter((r) => r.includes('PHPSESSID'))).toEqual([]);
  });
});
