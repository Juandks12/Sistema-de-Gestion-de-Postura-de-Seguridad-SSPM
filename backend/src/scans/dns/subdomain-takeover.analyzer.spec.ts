import { analyzeSubdomainTakeover } from './subdomain-takeover.analyzer';
import * as httpClient from '../web/http-client';

jest.mock('../web/http-client', () => ({
  ...jest.requireActual('../web/http-client'),
  httpProbe: jest.fn(),
}));

describe('subdomain-takeover.analyzer', () => {
  const httpProbeMock = jest.mocked(httpClient.httpProbe);

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('detecta Subdomain Takeover en GitHub Pages cuando responde con 404 y firma de sitio no reclamado', async () => {
    httpProbeMock.mockImplementation(async (url: string) => {
      if (url.includes('docs.comercio.com')) {
        return {
          ok: true,
          status: 404,
          finalUrl: url,
          contentType: 'text/html',
          body: Buffer.from("<html><body>There isn't a GitHub Pages site here.</body></html>"),
          headers: {},
          hops: [],
          error: null,
        } as any;
      }
      return { ok: false, status: 500 } as any;
    });

    const cnames = [
      { subdomain: 'docs.comercio.com', cname: 'comercio.github.io' },
    ];

    const findings = await analyzeSubdomainTakeover(cnames, {
      allowPrivate: false,
      signal: new AbortController().signal,
      timeoutMs: 5000,
    });

    expect(findings).toHaveLength(1);
    const finding = findings[0];
    expect(finding.ruleId).toBe('DNS-SUBDOMAIN-TAKEOVER');
    expect(finding.evidence?.service).toBe('GitHub Pages');
    expect(finding.evidence?.cname).toBe('comercio.github.io');
  });

  it('detecta Subdomain Takeover en AWS S3 Bucket huérfano con firma NoSuchBucket', async () => {
    httpProbeMock.mockImplementation(async (url: string) => {
      if (url.includes('assets.comercio.com')) {
        return {
          ok: true,
          status: 404,
          finalUrl: url,
          contentType: 'application/xml',
          body: Buffer.from('<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>'),
          headers: {},
          hops: [],
          error: null,
        } as any;
      }
      return { ok: false, status: 500 } as any;
    });

    const cnames = [
      { subdomain: 'assets.comercio.com', cname: 'assets-comercio.s3.amazonaws.com' },
    ];

    const findings = await analyzeSubdomainTakeover(cnames, {
      allowPrivate: false,
      signal: new AbortController().signal,
      timeoutMs: 5000,
    });

    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('DNS-SUBDOMAIN-TAKEOVER');
    expect(findings[0].evidence?.service).toBe('AWS S3 Bucket');
  });

  it('no genera hallazgo si el subdominio responde 200 con contenido legítimo', async () => {
    httpProbeMock.mockImplementation(async (url: string) => {
      return {
        ok: true,
        status: 200,
        finalUrl: url,
        contentType: 'text/html',
        body: Buffer.from('<html><body>Active App</body></html>'),
        headers: {},
        hops: [],
        error: null,
      } as any;
    });

    const cnames = [
      { subdomain: 'tienda.comercio.com', cname: 'comercio.myshopify.com' },
    ];

    const findings = await analyzeSubdomainTakeover(cnames, {
      allowPrivate: false,
      signal: new AbortController().signal,
      timeoutMs: 5000,
    });

    expect(findings).toHaveLength(0);
  });
});
