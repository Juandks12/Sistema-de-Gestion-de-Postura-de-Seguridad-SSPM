import { fakeDns } from '../../common/dns/fake-dns';
import { caaCandidates, lookupCaa } from './caa';

describe('CAA (RFC 8659)', () => {
  describe('caaCandidates', () => {
    it('genera candidatos de tree climbing hasta 2 etiquetas', () => {
      expect(caaCandidates('shop.sub.example.com')).toEqual([
        'shop.sub.example.com',
        'sub.example.com',
        'example.com',
      ]);
      expect(caaCandidates('example.com')).toEqual(['example.com']);
    });
  });

  describe('lookupCaa', () => {
    it('retorna missing si no hay registros CAA', async () => {
      const dns = fakeDns({});
      const res = await lookupCaa('example.com', dns);
      expect(res.status).toBe('missing');
      expect(res.inherited).toBe(false);
      expect(res.records).toHaveLength(0);
    });

    it('extrae correctamente las etiquetas issue, issuewild e iodef', async () => {
      const dns = fakeDns({
        caa: {
          'example.com': [
            { critical: 0, issue: 'letsencrypt.org' },
            { critical: 0, issuewild: ';' },
            { critical: 0, iodef: 'mailto:security@example.com' },
          ],
        },
      });

      const res = await lookupCaa('example.com', dns);
      expect(res.status).toBe('valid');
      expect(res.inherited).toBe(false);
      expect(res.issue).toEqual(['letsencrypt.org']);
      expect(res.issuewild).toEqual([';']);
      expect(res.iodef).toEqual(['mailto:security@example.com']);
    });

    it('hereda los registros CAA del dominio superior si el subdominio no tiene (tree climbing)', async () => {
      const dns = fakeDns({
        caa: {
          'example.com': [{ critical: 0, issue: 'digicert.com' }],
        },
      });

      const res = await lookupCaa('mail.corp.example.com', dns);
      expect(res.status).toBe('valid');
      expect(res.inherited).toBe(true);
      expect(res.domain).toBe('example.com');
      expect(res.issue).toEqual(['digicert.com']);
    });

    it('detecta banderas críticas no reconocidas como inválidas', async () => {
      const dns = fakeDns({
        caa: {
          'example.com': [{ critical: 64, issue: 'letsencrypt.org' }], // bit 6 no permitido en RFC 8659
        },
      });

      const res = await lookupCaa('example.com', dns);
      expect(res.status).toBe('invalid');
      expect(res.error).toContain('Bandera crítica no reconocida');
    });

    it('propaga error DNS si ocurre un fallo de servidor', async () => {
      const dns = fakeDns({
        caa: {
          'example.com': 'SERVFAIL',
        },
      });

      const res = await lookupCaa('example.com', dns);
      expect(res.status).toBe('invalid');
      expect(res.error).toContain('ESERVFAIL');
    });
  });
});
