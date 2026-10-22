import {
  extractFormsFromHtml,
  extractLinksFromHtml,
  extractScriptsFromHtml,
  crawlEcommerceSite,
} from './ecommerce-crawler';
import * as httpClient from './http-client';

jest.mock('./http-client', () => ({
  ...jest.requireActual('./http-client'),
  httpProbe: jest.fn(),
}));

describe('ecommerce-crawler', () => {
  const httpProbeMock = jest.mocked(httpClient.httpProbe);

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('extractLinksFromHtml', () => {
    it('extrae únicamente enlaces del mismo origen y normaliza URLs', () => {
      const html = `
        <div>
          <a href="/checkout">Ir a Pagar</a>
          <a href="https://example.com/carrito#step1">Carrito</a>
          <a href="https://other.com/external">Externo</a>
          <a href="javascript:void(0)">JS</a>
          <a href="mailto:support@example.com">Email</a>
        </div>
      `;
      const links = extractLinksFromHtml(html, 'https://example.com/home');
      expect(links).toEqual([
        'https://example.com/checkout',
        'https://example.com/carrito',
      ]);
    });
  });

  describe('extractScriptsFromHtml', () => {
    it('identifica scripts internos y externos con atributos SRI', () => {
      const html = `
        <script src="/static/app.js"></script>
        <script src="https://cdn.thirdparty.com/tracker.js"></script>
        <script src="https://cdn.example.com/secure.js" integrity="sha384-xyz" crossorigin="anonymous"></script>
      `;
      const scripts = extractScriptsFromHtml(html, 'https://example.com/');
      expect(scripts).toHaveLength(3);

      const internal = scripts.find((s) => s.src.includes('/static/app.js'));
      expect(internal?.isExternal).toBe(false);

      const externalWithoutSri = scripts.find((s) => s.src.includes('thirdparty.com'));
      expect(externalWithoutSri?.isExternal).toBe(true);
      expect(externalWithoutSri?.integrity).toBeUndefined();

      const externalWithSri = scripts.find((s) => s.src.includes('secure.js'));
      expect(externalWithSri?.integrity).toBe('sha384-xyz');
      expect(externalWithSri?.crossorigin).toBe('anonymous');
    });
  });

  describe('extractFormsFromHtml', () => {
    it('detecta formularios con campos de contraseña y tarjeta de crédito', () => {
      const html = `
        <form method="POST" action="/api/checkout">
          <input type="text" name="cc-num" />
          <input type="text" name="cvv" />
          <input type="password" name="password" />
        </form>
        <form method="GET" action="/search">
          <input type="text" name="q" />
        </form>
      `;
      const forms = extractFormsFromHtml(html, 'https://example.com/');
      expect(forms).toHaveLength(2);

      const sensitiveForm = forms[0];
      expect(sensitiveForm.method).toBe('POST');
      expect(sensitiveForm.action).toBe('https://example.com/api/checkout');
      expect(sensitiveForm.hasCardInput).toBe(true);
      expect(sensitiveForm.hasPasswordInput).toBe(true);

      const searchForm = forms[1];
      expect(searchForm.hasCardInput).toBe(false);
      expect(searchForm.hasPasswordInput).toBe(false);
    });
  });

  describe('crawlEcommerceSite', () => {
    it('rastrea robots.txt, identifica rutas sensibles expuestas y rastrea páginas', async () => {
      const initialHtml = `
        <html><body>
          <a href="/checkout">Checkout</a>
          <a href="/login">Login</a>
        </body></html>
      `;

      httpProbeMock.mockImplementation(async (url: string) => {
        if (url.endsWith('/robots.txt')) {
          return {
            ok: true,
            status: 200,
            finalUrl: url,
            contentType: 'text/plain',
            body: Buffer.from('User-agent: *\nDisallow: /admin/\nDisallow: /checkout/\nSitemap: https://example.com/sitemap.xml'),
            headers: {},
            hops: [],
            error: null,
          } as any;
        }

        if (url.includes('/admin/')) {
          return {
            ok: true,
            status: 200,
            finalUrl: url,
            contentType: 'text/html',
            body: Buffer.from('<h1>Admin Login</h1>'),
            headers: {},
            hops: [],
            error: null,
          } as any;
        }

        if (url.endsWith('/sitemap.xml')) {
          return {
            ok: true,
            status: 200,
            finalUrl: url,
            contentType: 'application/xml',
            body: Buffer.from('<urlset><loc>https://example.com/tienda</loc></urlset>'),
            headers: {},
            hops: [],
            error: null,
          } as any;
        }

        return {
          ok: true,
          status: 200,
          finalUrl: url,
          contentType: 'text/html',
          body: Buffer.from('<html><body>OK</body></html>'),
          headers: {},
          hops: [],
          error: null,
        } as any;
      });

      const initialResult = {
        ok: true,
        status: 200,
        finalUrl: 'https://example.com/',
        contentType: 'text/html',
        body: Buffer.from(initialHtml),
        headers: {},
        hops: [],
        error: null,
      } as any;

      const result = await crawlEcommerceSite('https://example.com/', initialResult, {
        allowPrivate: false,
        signal: new AbortController().signal,
        timeoutMs: 5000,
      });

      expect(result.robotsTxt.found).toBe(true);
      expect(result.robotsTxt.disallows).toContain('/admin/');
      expect(result.findings.some((f) => f.ruleId === 'PATH-ROBOTS-SENSITIVE-EXPOSED')).toBe(true);
      expect(result.pages.length).toBeGreaterThan(1);
    });
  });
});
