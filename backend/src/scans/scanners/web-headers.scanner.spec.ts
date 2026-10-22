import { ConfigService } from '@nestjs/config';
import { AssetType } from '@prisma/client';
import { WebHeadersScanner } from './web-headers.scanner';
import * as httpClient from '../web/http-client';
import { ScanContext } from '../scanner.interface';

jest.mock('../web/http-client', () => ({
  ...jest.requireActual('../web/http-client'),
  httpProbe: jest.fn(),
}));

describe('WebHeadersScanner', () => {
  const httpProbeMock = jest.mocked(httpClient.httpProbe);
  let scanner: WebHeadersScanner;
  let configService: ConfigService;

  beforeEach(() => {
    jest.clearAllMocks();
    configService = {
      get: jest.fn((key: string) => {
        if (key === 'WEB_REQUEST_TIMEOUT_MS') return 5000;
        return undefined;
      }),
    } as any;
    scanner = new WebHeadersScanner(configService);
  });

  it('ejecuta la inspección completa de cabeceras, tecnologías y módulos comerciales', async () => {
    const ctx: ScanContext = {
      scanId: 'scan-1',
      organizationId: 'org-1',
      asset: {
        id: 'asset-1',
        organizationId: 'org-1',
        type: AssetType.DOMAIN,
        value: 'comercio.test',
        criticality: 'HIGH',
        status: 'ACTIVE',
        tags: [],
        createdAt: new Date(),
        updatedAt: new Date(),
      } as any,
      target: {
        address: '93.184.216.34',
        family: 4,
        resolvedAddresses: ['93.184.216.34'],
      },
      allowPrivate: false,
      openPorts: [{ port: 443, protocol: 'tcp', serviceName: 'https', tunnel: 'ssl' }],
      signal: new AbortController().signal,
      timeoutMs: 5000,
    };

    httpProbeMock.mockImplementation(async (url: string) => {
      if (url.includes('/robots.txt')) {
        return {
          ok: true,
          status: 200,
          finalUrl: url,
          contentType: 'text/plain',
          body: Buffer.from('User-agent: *\nDisallow: /admin\nSitemap: https://comercio.test/sitemap.xml'),
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
        body: Buffer.from(`
          <html>
            <head>
              <meta name="generator" content="WordPress 6.4.2" />
              <link rel="stylesheet" href="/wp-content/themes/store/style.css" />
            </head>
            <body>
              <h1>Comercio</h1>
              <a href="/checkout">Pagar</a>
              <script src="/app.js"></script>
            </body>
          </html>
        `),
        headers: {
          server: 'nginx/1.24.0',
          'strict-transport-security': 'max-age=31536000',
        },
        hops: [{ url, status: 200 }],
        error: null,
      } as any;
    });

    const outcome = await scanner.run(ctx);

    expect(outcome).toBeDefined();
    expect(outcome.summary.targetsReachable).toBeGreaterThan(0);
    expect(outcome.summary.technologies).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: 'WordPress' }),
        expect.objectContaining({ name: 'Nginx' }),
      ]),
    );
    expect(outcome.rawResult).toHaveProperty('deepInspection');
  });
});
