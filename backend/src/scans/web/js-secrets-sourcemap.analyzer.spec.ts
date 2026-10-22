import {
  analyzeJsSecretsAndSourceMaps,
  redactToken,
} from './js-secrets-sourcemap.analyzer';
import { CrawledPage } from './ecommerce-crawler';
import * as httpClient from './http-client';

jest.mock('./http-client', () => ({
  ...jest.requireActual('./http-client'),
  httpProbe: jest.fn(),
}));

describe('js-secrets-sourcemap.analyzer', () => {
  const httpProbeMock = jest.mocked(httpClient.httpProbe);

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('redactToken', () => {
    it('redacta tokens sensibles conservando primeros y últimos 4 caracteres', () => {
      const sample = ['sk', 'live', '1234567890abcdefghijklmn'].join('_');
      expect(redactToken(sample)).toBe('sk_l****klmn');
      expect(redactToken('short')).toBe('****');
    });
  });

  describe('analyzeJsSecretsAndSourceMaps', () => {
    it('detecta fuga de Stripe y MercadoPago en bundle JS con ofuscación en evidencia', async () => {
      const pages: CrawledPage[] = [
        {
          url: 'https://comercio.com/',
          status: 200,
          html: '<html><body>Home</body></html>',
          contentType: 'text/html',
          internalLinks: [],
          forms: [],
          scripts: [{ src: 'https://comercio.com/bundle.js', isExternal: false }],
        },
      ];

      const dummyStripe = ['sk', 'live', '51Abcdefghijklmnop1234567890xyz'].join('_');
      const dummyMp = ['APP_USR', '1234567890123456', '123456', 'abcdef1234567890abcdef1234567890', '123456789'].join('-');
      const jsBody = `
        const stripeKey = "${dummyStripe}";
        const mpToken = "${dummyMp}";
        console.log("App initialized");
      `;

      httpProbeMock.mockImplementation(async (url: string) => {
        if (url === 'https://comercio.com/bundle.js') {
          return {
            ok: true,
            status: 200,
            finalUrl: url,
            contentType: 'application/javascript',
            body: Buffer.from(jsBody),
            headers: {},
            hops: [],
            error: null,
          } as any;
        }

        // Para la prueba de .map devolver 404
        return {
          ok: false,
          status: 404,
          finalUrl: url,
          contentType: 'text/html',
          body: Buffer.from(''),
          headers: {},
          hops: [],
          error: null,
        } as any;
      });

      const result = await analyzeJsSecretsAndSourceMaps(pages, {
        allowPrivate: false,
        signal: new AbortController().signal,
        timeoutMs: 5000,
      });

      expect(result.scriptsAnalyzed).toBe(1);
      expect(result.secretsFoundCount).toBeGreaterThanOrEqual(2);

      const secretFindings = result.findings.filter((f) => f.ruleId === 'WEB-JS-SECRET-LEAK');
      expect(secretFindings).toHaveLength(2);

      const stripeFinding = secretFindings.find((f) => f.title?.includes('Stripe'));
      expect(stripeFinding).toBeDefined();
      const redacted = (stripeFinding?.evidence?.redactedMatches as string[])[0];
      expect(redacted).toContain('****');
      expect(redacted).not.toEqual(dummyStripe);
    });

    it('detecta archivos .js.map expuestos en producción (PATH-SOURCEMAP-EXPOSED)', async () => {
      const pages: CrawledPage[] = [
        {
          url: 'https://comercio.com/',
          status: 200,
          html: '<html><body>Home</body></html>',
          contentType: 'text/html',
          internalLinks: [],
          forms: [],
          scripts: [{ src: 'https://comercio.com/app.js', isExternal: false }],
        },
      ];

      const jsBody = `console.log("Hello");\n//# sourceMappingURL=app.js.map`;
      const mapBody = JSON.stringify({
        version: 3,
        sources: ['src/index.ts', 'src/components/Checkout.tsx'],
        mappings: 'AAAA;',
      });

      httpProbeMock.mockImplementation(async (url: string) => {
        if (url === 'https://comercio.com/app.js') {
          return {
            ok: true,
            status: 200,
            finalUrl: url,
            contentType: 'application/javascript',
            body: Buffer.from(jsBody),
            headers: {},
            hops: [],
            error: null,
          } as any;
        }

        if (url === 'https://comercio.com/app.js.map') {
          return {
            ok: true,
            status: 200,
            finalUrl: url,
            contentType: 'application/json',
            body: Buffer.from(mapBody),
            headers: {},
            hops: [],
            error: null,
          } as any;
        }

        return { ok: false, status: 404 } as any;
      });

      const result = await analyzeJsSecretsAndSourceMaps(pages, {
        allowPrivate: false,
        signal: new AbortController().signal,
        timeoutMs: 5000,
      });

      expect(result.sourceMapsExposed).toContain('https://comercio.com/app.js.map');
      const mapFinding = result.findings.find((f) => f.ruleId === 'PATH-SOURCEMAP-EXPOSED');
      expect(mapFinding).toBeDefined();
      expect(mapFinding?.location).toBe('https://comercio.com/app.js.map');
    });
  });
});
