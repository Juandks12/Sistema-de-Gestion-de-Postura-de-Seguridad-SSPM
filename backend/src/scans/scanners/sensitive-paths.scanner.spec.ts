import { ConfigService } from '@nestjs/config';
import { AssetType } from '@prisma/client';
import { SensitivePathsScanner } from './sensitive-paths.scanner';
import * as httpClient from '../web/http-client';
import { ScanContext } from '../scanner.interface';

jest.mock('../web/http-client', () => ({
  ...jest.requireActual('../web/http-client'),
  httpProbe: jest.fn(),
}));

describe('SensitivePathsScanner', () => {
  const httpProbeMock = jest.mocked(httpClient.httpProbe);
  let scanner: SensitivePathsScanner;
  let configService: ConfigService;

  beforeEach(() => {
    jest.clearAllMocks();
    configService = {
      get: jest.fn((key: string) => {
        if (key === 'WEB_REQUEST_TIMEOUT_MS') return 5000;
        if (key === 'WEB_PATHS_CONCURRENCY') return 2;
        return undefined;
      }),
    } as any;
    scanner = new SensitivePathsScanner(configService);
  });

  const baseCtx: ScanContext = {
    scanId: 'scan-sens-1',
    organizationId: 'org-1',
    asset: {
      id: 'asset-1',
      organizationId: 'org-1',
      type: AssetType.DOMAIN,
      value: 'api.example.com',
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

  it('detecta swagger expuesto y profundiza en operaciones sensibles sin autenticación', async () => {
    const mockOpenApiSpec = {
      openapi: '3.0.0',
      paths: {
        '/api/admin/users': {
          delete: { summary: 'Delete user' },
        },
      },
    };

    httpProbeMock.mockImplementation(async (url: string) => {
      // 1. Base connectivity check (target.url)
      if (url === 'https://api.example.com' || url === 'http://api.example.com') {
        return {
          ok: true,
          status: 200,
          finalUrl: url,
          contentType: 'text/html',
          body: Buffer.from('OK'),
          headers: {},
          hops: [],
        } as any;
      }

      // 2. Canary probe (returns clean 404)
      if (url.includes('-sspm-probe')) {
        return {
          ok: true,
          status: 404,
          finalUrl: url,
          contentType: 'text/html',
          body: Buffer.from('Not Found'),
          headers: {},
          hops: [],
        } as any;
      }

      // 3. /swagger.json matches
      if (url.endsWith('/swagger.json')) {
        return {
          ok: true,
          status: 200,
          finalUrl: url,
          contentType: 'application/json',
          body: Buffer.from(JSON.stringify(mockOpenApiSpec)),
          headers: { 'content-type': 'application/json' },
          hops: [],
        } as any;
      }

      // Default: 404
      return {
        ok: true,
        status: 404,
        finalUrl: url,
        contentType: 'text/html',
        body: Buffer.from('Not found'),
        headers: {},
        hops: [],
      } as any;
    });

    const outcome = await scanner.run(baseCtx);

    expect(outcome).toBeDefined();
    expect(outcome.summary.findingsCount).toBeGreaterThan(0);

    const swaggerFinding = outcome.findings.find((f) => f.ruleId === 'API-SWAGGER-EXPOSED');
    expect(swaggerFinding).toBeDefined();

    // Verificamos que el inspector profundo generó el hallazgo de operaciones no autenticadas
    const deepFinding = outcome.findings.find(
      (f) => f.ruleId === 'API-DOCS-UNAUTHENTICATED-OPERATIONS',
    );
    expect(deepFinding).toBeDefined();
  });

  it('detecta fuga de stack trace en la respuesta canary de error', async () => {
    httpProbeMock.mockImplementation(async (url: string) => {
      if (url === 'https://api.example.com') {
        return {
          ok: true,
          status: 200,
          finalUrl: url,
          contentType: 'text/html',
          body: Buffer.from('OK'),
          headers: {},
          hops: [],
        } as any;
      }

      if (url.includes('-sspm-probe')) {
        return {
          ok: true,
          status: 500,
          finalUrl: url,
          contentType: 'text/plain',
          body: Buffer.from(`
            TypeError: Cannot read properties of undefined (reading 'handler')
                at Express.handle (/var/www/node_modules/express/router.js:150:20)
                at /var/www/server.ts:88:14
          `),
          headers: {},
          hops: [],
        } as any;
      }

      return {
        ok: true,
        status: 404,
        finalUrl: url,
        contentType: 'text/html',
        body: Buffer.from('Not found'),
        headers: {},
        hops: [],
      } as any;
    });

    const outcome = await scanner.run(baseCtx);

    const traceFinding = outcome.findings.find((f) => f.ruleId === 'WEB-DEBUG-STACKTRACE-LEAK');
    expect(traceFinding).toBeDefined();

    const pathFinding = outcome.findings.find((f) => f.ruleId === 'WEB-INTERNAL-PATH-DISCLOSURE');
    expect(pathFinding).toBeDefined();
  });
});
