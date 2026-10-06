import { fakeDns } from '../../common/dns/fake-dns';
import { lookupTlsRpt, parseTlsRptRecord } from './tls-rpt';

describe('TLS-RPT (RFC 8460)', () => {
  describe('parseTlsRptRecord', () => {
    it('parsea correctamente un registro DNS TXT válido con un rua', () => {
      const res = parseTlsRptRecord('v=TLSRPTv1; rua=mailto:tls-reports@example.com');
      expect(res.record).toEqual({
        version: 'TLSRPTv1',
        rua: ['mailto:tls-reports@example.com'],
        raw: 'v=TLSRPTv1; rua=mailto:tls-reports@example.com',
      });
      expect(res.error).toBeUndefined();
    });

    it('soporta múltiples direcciones en rua separadas por comas', () => {
      const res = parseTlsRptRecord('v=TLSRPTv1; rua=mailto:tls1@example.com, mailto:tls2@example.com');
      expect(res.record?.rua).toEqual(['mailto:tls1@example.com', 'mailto:tls2@example.com']);
    });

    it('rechaza registros sin versión TLSRPTv1', () => {
      const res = parseTlsRptRecord('v=OTHER; rua=mailto:reports@example.com');
      expect(res.record).toBeNull();
      expect(res.error).toContain('Versión TLS-RPT inválida o ausente');
    });

    it('rechaza registros sin directiva rua', () => {
      const res = parseTlsRptRecord('v=TLSRPTv1');
      expect(res.record).toBeNull();
      expect(res.error).toContain('Directiva rua');
    });
  });

  describe('lookupTlsRpt', () => {
    it('reporta missing cuando no existe registro _smtp._tls.<domain>', async () => {
      const dns = fakeDns({});
      const res = await lookupTlsRpt('example.com', dns);
      expect(res.status).toBe('missing');
      expect(res.record).toBeNull();
    });

    it('valida exitosamente el registro cuando existe', async () => {
      const dns = fakeDns({
        txt: {
          '_smtp._tls.example.com': ['v=TLSRPTv1; rua=mailto:tls@example.com'],
        },
      });

      const res = await lookupTlsRpt('example.com', dns);
      expect(res.status).toBe('valid');
      expect(res.record?.rua).toEqual(['mailto:tls@example.com']);
    });

    it('reporta invalid si existen múltiples registros TLS-RPT', async () => {
      const dns = fakeDns({
        txt: {
          '_smtp._tls.example.com': [
            'v=TLSRPTv1; rua=mailto:a@example.com',
            'v=TLSRPTv1; rua=mailto:b@example.com',
          ],
        },
      });

      const res = await lookupTlsRpt('example.com', dns);
      expect(res.status).toBe('invalid');
      expect(res.error).toContain('Se encontraron 2 registros TLS-RPT');
    });
  });
});
