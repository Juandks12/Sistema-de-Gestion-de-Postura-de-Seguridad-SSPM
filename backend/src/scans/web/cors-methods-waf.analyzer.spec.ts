import { analyzeCorsMethodsAndWaf } from './cors-methods-waf.analyzer';
import * as httpClient from './http-client';

jest.mock('./http-client', () => ({
  ...jest.requireActual('./http-client'),
  httpProbe: jest.fn(),
}));

describe('cors-methods-waf.analyzer', () => {
  const httpProbeMock = jest.mocked(httpClient.httpProbe);

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('detecta reflexión arbitraria de origen CORS con credenciales (HDR-CORS-ORIGIN-REFLECTION)', async () => {
    httpProbeMock.mockImplementation(async (url: string, opts?: any) => {
      if (opts?.headers?.origin === 'https://sspm-probe.invalid') {
        return {
          ok: true,
          status: 200,
          finalUrl: url,
          contentType: 'text/html',
          body: Buffer.from(''),
          headers: {
            'access-control-allow-origin': 'https://sspm-probe.invalid',
            'access-control-allow-credentials': 'true',
          },
          hops: [],
          error: null,
        } as any;
      }

      if (opts?.method === 'OPTIONS') {
        return {
          ok: true,
          status: 200,
          finalUrl: url,
          contentType: 'text/html',
          body: Buffer.from(''),
          headers: { allow: 'GET, POST' },
          hops: [],
          error: null,
        } as any;
      }

      return { ok: false, status: 500 } as any;
    });

    const result = await analyzeCorsMethodsAndWaf(
      'https://api.comercio.com',
      { 'cf-ray': '1234567890' },
      {
        allowPrivate: false,
        signal: new AbortController().signal,
        timeoutMs: 5000,
      },
    );

    expect(result.corsOriginReflected).toBe(true);
    const corsFinding = result.findings.find((f) => f.ruleId === 'HDR-CORS-ORIGIN-REFLECTION');
    expect(corsFinding).toBeDefined();
    expect(corsFinding?.evidence?.reflectedOrigin).toBe('https://sspm-probe.invalid');
  });

  it('detecta métodos HTTP peligrosos (TRACE, DELETE, PUT) mediante sonda OPTIONS', async () => {
    httpProbeMock.mockImplementation(async (url: string, opts?: any) => {
      if (opts?.method === 'OPTIONS') {
        return {
          ok: true,
          status: 200,
          finalUrl: url,
          contentType: 'text/html',
          body: Buffer.from(''),
          headers: { allow: 'GET, POST, TRACE, PUT, DELETE' },
          hops: [],
          error: null,
        } as any;
      }
      return { ok: true, status: 200, headers: {}, body: Buffer.from('') } as any;
    });

    const result = await analyzeCorsMethodsAndWaf(
      'https://comercio.com',
      {},
      {
        allowPrivate: false,
        signal: new AbortController().signal,
        timeoutMs: 5000,
      },
    );

    expect(result.dangerousMethodsAllowed).toContain('TRACE');
    expect(result.dangerousMethodsAllowed).toContain('PUT');
    expect(result.dangerousMethodsAllowed).toContain('DELETE');
    expect(result.findings.some((f) => f.ruleId === 'WEB-HTTP-METHODS-DANGEROUS')).toBe(true);
  });

  it('detecta proveedor WAF a través de cabeceras de respuesta (Cloudflare)', async () => {
    httpProbeMock.mockImplementation(async () => ({ ok: true, status: 200, headers: {}, body: Buffer.from('') } as any));

    const result = await analyzeCorsMethodsAndWaf(
      'https://comercio.com',
      {
        server: 'cloudflare',
        'cf-ray': '89b27d14acde89-BOG',
      },
      {
        allowPrivate: false,
        signal: new AbortController().signal,
        timeoutMs: 5000,
      },
      true,
    );

    expect(result.wafDetected).toBe(true);
    expect(result.wafProvider).toBe('Cloudflare');
    expect(result.findings.some((f) => f.ruleId === 'WEB-WAF-ABSENT')).toBe(false);
  });

  it('reporta WEB-WAF-ABSENT si no hay WAF en un comercio con login/checkout', async () => {
    httpProbeMock.mockImplementation(async () => ({ ok: true, status: 200, headers: {}, body: Buffer.from('') } as any));

    const result = await analyzeCorsMethodsAndWaf(
      'https://comercio.com',
      { server: 'Apache/2.4.52' },
      {
        allowPrivate: false,
        signal: new AbortController().signal,
        timeoutMs: 5000,
      },
      true, // hasSensitiveFeatures
    );

    expect(result.wafDetected).toBe(false);
    expect(result.findings.some((f) => f.ruleId === 'WEB-WAF-ABSENT')).toBe(true);
  });
});
