import { fakeDns } from '../../common/dns/fake-dns';
import { lookupMtaSts, parseMtaStsDnsRecord, parseMtaStsPolicy } from './mta-sts';

describe('MTA-STS (RFC 8461)', () => {
  describe('parseMtaStsDnsRecord', () => {
    it('parsea correctamente un registro DNS TXT válido', () => {
      const res = parseMtaStsDnsRecord('v=STSv1; id=2026093001');
      expect(res.record).toEqual({
        version: 'STSv1',
        id: '2026093001',
        raw: 'v=STSv1; id=2026093001',
      });
      expect(res.error).toBeUndefined();
    });

    it('rechaza registros con versión distinta a STSv1', () => {
      const res = parseMtaStsDnsRecord('v=STSv2; id=123');
      expect(res.record).toBeNull();
      expect(res.error).toContain('Versión MTA-STS inválida');
    });

    it('rechaza registros sin id o con caracteres no alfanuméricos', () => {
      const res = parseMtaStsDnsRecord('v=STSv1; id=bad_id!');
      expect(res.record).toBeNull();
      expect(res.error).toContain('Identificador de política "id"');
    });
  });

  describe('parseMtaStsPolicy', () => {
    it('parsea una política válida con mode enforce y directivas mx', () => {
      const text = `
        version: STSv1
        mode: enforce
        mx: mail.example.com
        mx: *.example.com
        max_age: 604800
      `;
      const res = parseMtaStsPolicy(text);
      expect(res.policy).toEqual({
        version: 'STSv1',
        mode: 'enforce',
        maxAge: 604800,
        mx: ['mail.example.com', '*.example.com'],
        raw: text,
      });
      expect(res.error).toBeUndefined();
    });

    it('rechaza políticas sin directiva mx en modo enforce', () => {
      const text = `
        version: STSv1
        mode: enforce
        max_age: 86400
      `;
      const res = parseMtaStsPolicy(text);
      expect(res.policy).toBeNull();
      expect(res.error).toContain('requiere al menos una directiva mx');
    });

    it('permite modo testing con directivas mx', () => {
      const text = `
        version: STSv1
        mode: testing
        mx: mx1.example.com
        max_age: 86400
      `;
      const res = parseMtaStsPolicy(text);
      expect(res.policy?.mode).toBe('testing');
    });

    it('rechaza modo inválido', () => {
      const text = `
        version: STSv1
        mode: permissive
        mx: mx1.example.com
        max_age: 86400
      `;
      const res = parseMtaStsPolicy(text);
      expect(res.policy).toBeNull();
      expect(res.error).toContain('Directiva mode ausente o no permitida');
    });
  });

  describe('lookupMtaSts', () => {
    it('reporta missing si no existe registro _mta-sts.<domain>', async () => {
      const dns = fakeDns({});
      const res = await lookupMtaSts('example.com', dns);
      expect(res.status).toBe('missing');
      expect(res.policy).toBeNull();
    });

    it('valida exitosamente política HTTPS cuando DNS y archivo coinciden', async () => {
      const dns = fakeDns({
        txt: {
          '_mta-sts.example.com': ['v=STSv1; id=2026093001'],
        },
      });

      const mockFetchPolicy = jest.fn().mockResolvedValue({
        ok: true,
        status: 200,
        text: 'version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 604800',
      });

      const res = await lookupMtaSts('example.com', dns, mockFetchPolicy);
      expect(res.status).toBe('valid');
      expect(res.policy?.mode).toBe('enforce');
      expect(res.policy?.mx).toEqual(['mail.example.com']);
      expect(mockFetchPolicy).toHaveBeenCalledWith(
        'https://mta-sts.example.com/.well-known/mta-sts.txt',
        undefined,
      );
    });

    it('reporta invalid si el servidor HTTPS responde 404', async () => {
      const dns = fakeDns({
        txt: {
          '_mta-sts.example.com': ['v=STSv1; id=2026093001'],
        },
      });

      const mockFetchPolicy = jest.fn().mockResolvedValue({
        ok: false,
        status: 404,
        text: '',
      });

      const res = await lookupMtaSts('example.com', dns, mockFetchPolicy);
      expect(res.status).toBe('invalid');
      expect(res.error).toContain('Servidor HTTPS respondió status 404');
    });

    it('reporta invalid si existen múltiples registros DNS MTA-STS', async () => {
      const dns = fakeDns({
        txt: {
          '_mta-sts.example.com': ['v=STSv1; id=1', 'v=STSv1; id=2'],
        },
      });

      const res = await lookupMtaSts('example.com', dns);
      expect(res.status).toBe('invalid');
      expect(res.error).toContain('Se encontraron 2 registros MTA-STS');
    });
  });
});
