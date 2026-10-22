import { analyzeCmsAndEcommercePlatform } from './cms-ecommerce.analyzer';
import * as httpClient from './http-client';

jest.mock('./http-client', () => ({
  ...jest.requireActual('./http-client'),
  httpProbe: jest.fn(),
}));

describe('cms-ecommerce.analyzer', () => {
  const httpProbeMock = jest.mocked(httpClient.httpProbe);

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('detecta enumeración de usuarios de WordPress (/wp-json/wp/v2/users)', async () => {
    httpProbeMock.mockImplementation(async (url: string) => {
      if (url.includes('/wp-json/wp/v2/users')) {
        return {
          ok: true,
          status: 200,
          finalUrl: url,
          contentType: 'application/json',
          body: Buffer.from(JSON.stringify([{ id: 1, name: 'Admin Shop', slug: 'admin' }])),
          headers: {},
          hops: [],
          error: null,
        } as any;
      }
      return { ok: false, status: 404 } as any;
    });

    const result = await analyzeCmsAndEcommercePlatform('https://mitienda.com', {
      allowPrivate: false,
      signal: new AbortController().signal,
      timeoutMs: 5000,
    });

    expect(result.wpUserEnumerationExposed).toBe(true);
    const finding = result.findings.find((f) => f.ruleId === 'CMS-WP-USER-ENUMERATION');
    expect(finding).toBeDefined();
    expect(finding?.evidence?.discoveredUsersCount).toBe(1);
  });

  it('detecta XML-RPC activo en WordPress (/xmlrpc.php)', async () => {
    httpProbeMock.mockImplementation(async (url: string) => {
      if (url.includes('/xmlrpc.php')) {
        return {
          ok: true,
          status: 200,
          finalUrl: url,
          contentType: 'text/plain',
          body: Buffer.from('XML-RPC server accepts POST requests only.'),
          headers: {},
          hops: [],
          error: null,
        } as any;
      }
      return { ok: false, status: 404 } as any;
    });

    const result = await analyzeCmsAndEcommercePlatform('https://mitienda.com', {
      allowPrivate: false,
      signal: new AbortController().signal,
      timeoutMs: 5000,
    });

    expect(result.wpXmlRpcEnabled).toBe(true);
    expect(result.findings.some((f) => f.ruleId === 'CMS-WP-XMLRPC-ENABLED')).toBe(true);
  });

  it('detecta debug.log expuesto con trazas de error de PHP', async () => {
    httpProbeMock.mockImplementation(async (url: string) => {
      if (url.includes('/wp-content/debug.log')) {
        return {
          ok: true,
          status: 200,
          finalUrl: url,
          contentType: 'text/plain',
          body: Buffer.from('[20-Oct-2026 12:00:00 UTC] PHP Fatal error: Uncaught Error in /var/www/wp-config.php:12\nStack trace: ...'),
          headers: {},
          hops: [],
          error: null,
        } as any;
      }
      return { ok: false, status: 404 } as any;
    });

    const result = await analyzeCmsAndEcommercePlatform('https://mitienda.com', {
      allowPrivate: false,
      signal: new AbortController().signal,
      timeoutMs: 5000,
    });

    expect(result.wpDebugLogExposed).toBe(true);
    expect(result.findings.some((f) => f.ruleId === 'CMS-WP-DEBUG-LOG-EXPOSED')).toBe(true);
  });

  it('detecta introspección activa de GraphQL', async () => {
    httpProbeMock.mockImplementation(async (url: string, opts?: any) => {
      if (url.endsWith('/graphql') && opts?.method === 'POST') {
        return {
          ok: true,
          status: 200,
          finalUrl: url,
          contentType: 'application/json',
          body: Buffer.from(JSON.stringify({ data: { __schema: { queryType: { name: 'Query' }, types: [] } } })),
          headers: {},
          hops: [],
          error: null,
        } as any;
      }
      return { ok: false, status: 404 } as any;
    });

    const result = await analyzeCmsAndEcommercePlatform('https://mitienda.com', {
      allowPrivate: false,
      signal: new AbortController().signal,
      timeoutMs: 5000,
    });

    expect(result.graphqlIntrospectionActive).toBe(true);
    expect(result.findings.some((f) => f.ruleId === 'API-GRAPHQL-INTROSPECTION')).toBe(true);
  });
});
