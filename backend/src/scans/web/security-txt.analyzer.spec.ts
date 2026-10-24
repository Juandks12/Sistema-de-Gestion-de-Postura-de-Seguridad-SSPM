import { analyzeSecurityTxt, parseSecurityTxt } from './security-txt.analyzer';
import * as httpClient from './http-client';

describe('security-txt.analyzer', () => {
  describe('parseSecurityTxt', () => {
    it('parsea correctamente directivas estándar RFC 9116', () => {
      const content = `
        # Política de divulgación responsable
        Contact: mailto:security@example.com
        Contact: https://example.com/security-report
        Expires: 2028-12-31T23:59:59.000Z
        Encryption: https://example.com/pgp-key.txt
        Acknowledgments: https://example.com/hall-of-fame
        Preferred-Languages: es, en
        Canonical: https://example.com/.well-known/security.txt
        Policy: https://example.com/disclosure-policy
        Hiring: https://example.com/jobs
      `;

      const parsed = parseSecurityTxt(content);
      expect(parsed.contact).toEqual([
        'mailto:security@example.com',
        'https://example.com/security-report',
      ]);
      expect(parsed.expires).toBe('2028-12-31T23:59:59.000Z');
      expect(parsed.encryption).toEqual(['https://example.com/pgp-key.txt']);
      expect(parsed.preferredLanguages).toBe('es, en');
      expect(parsed.policy).toBe('https://example.com/disclosure-policy');
      expect(parsed.hiring).toBe('https://example.com/jobs');
    });
  });

  describe('analyzeSecurityTxt', () => {
    let httpProbeSpy: jest.SpyInstance;

    beforeEach(() => {
      httpProbeSpy = jest.spyOn(httpClient, 'httpProbe');
    });

    afterEach(() => {
      httpProbeSpy.mockRestore();
    });

    it('reporta SEC-TXT-MISSING si el endpoint responde 404', async () => {
      httpProbeSpy.mockResolvedValueOnce({
        ok: true,
        status: 404,
        headers: {},
        body: Buffer.from('Not found'),
        requestedUrl: 'https://example.com/.well-known/security.txt',
        finalUrl: 'https://example.com/.well-known/security.txt',
        bodyTruncated: false,
        contentType: 'text/html',
        hops: [],
        durationMs: 50,
      });

      const res = await analyzeSecurityTxt('https://example.com');
      expect(res.status).toBe('missing');
      expect(res.findings).toHaveLength(1);
      expect(res.findings[0].ruleId).toBe('SEC-TXT-MISSING');
    });

    it('reporta SEC-TXT-INVALID si falta Contact o Expires', async () => {
      httpProbeSpy.mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: { 'content-type': 'text/plain' },
        body: Buffer.from('Preferred-Languages: es\nPolicy: https://example.com/policy'),
        requestedUrl: 'https://example.com/.well-known/security.txt',
        finalUrl: 'https://example.com/.well-known/security.txt',
        bodyTruncated: false,
        contentType: 'text/plain',
        hops: [],
        durationMs: 50,
      });

      const res = await analyzeSecurityTxt('https://example.com');
      expect(res.status).toBe('invalid');
      expect(res.findings).toHaveLength(1);
      expect(res.findings[0].ruleId).toBe('SEC-TXT-INVALID');
    });

    it('reporta SEC-TXT-EXPIRED si la fecha de Expires ya venció', async () => {
      httpProbeSpy.mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: { 'content-type': 'text/plain' },
        body: Buffer.from('Contact: mailto:sec@example.com\nExpires: 2020-01-01T00:00:00Z'),
        requestedUrl: 'https://example.com/.well-known/security.txt',
        finalUrl: 'https://example.com/.well-known/security.txt',
        bodyTruncated: false,
        contentType: 'text/plain',
        hops: [],
        durationMs: 50,
      });

      const res = await analyzeSecurityTxt('https://example.com');
      expect(res.status).toBe('expired');
      expect(res.findings).toHaveLength(1);
      expect(res.findings[0].ruleId).toBe('SEC-TXT-EXPIRED');
    });

    it('valida exitosamente un security.txt vigente y completo', async () => {
      httpProbeSpy.mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: { 'content-type': 'text/plain' },
        body: Buffer.from('Contact: mailto:sec@example.com\nExpires: 2030-01-01T00:00:00Z\nPolicy: https://example.com/policy'),
        requestedUrl: 'https://example.com/.well-known/security.txt',
        finalUrl: 'https://example.com/.well-known/security.txt',
        bodyTruncated: false,
        contentType: 'text/plain',
        hops: [],
        durationMs: 50,
      });

      const res = await analyzeSecurityTxt('https://example.com');
      expect(res.status).toBe('valid');
      expect(res.findings).toHaveLength(0);
      expect(res.directives?.contact).toEqual(['mailto:sec@example.com']);
    });
  });
});
