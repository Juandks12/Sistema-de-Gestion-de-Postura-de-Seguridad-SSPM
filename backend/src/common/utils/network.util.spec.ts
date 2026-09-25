import { AssetType } from '@prisma/client';
import { isPrivateOrReservedIp, normalizeAssetValue, validateAssetValue } from './network.util';

describe('network.util', () => {
  describe('isPrivateOrReservedIp', () => {
    it.each(['10.0.0.1', '172.16.5.5', '172.31.255.255', '192.168.1.1', '127.0.0.1', '169.254.1.1', '0.0.0.0', '224.0.0.1', '255.255.255.255', '::1', 'fe80::1', 'fd00::1', '::ffff:192.168.0.1'])(
      'marca %s como privada/reservada',
      (ip) => expect(isPrivateOrReservedIp(ip)).toBe(true),
    );

    it.each(['8.8.8.8', '45.33.32.156', '172.32.0.1', '1.1.1.1', '2606:4700:4700::1111'])(
      'marca %s como pública',
      (ip) => expect(isPrivateOrReservedIp(ip)).toBe(false),
    );
  });

  describe('normalizeAssetValue', () => {
    it('elimina esquema, ruta, puerto y punto final', () => {
      expect(normalizeAssetValue('  HTTPS://Example.COM:443/path?x=1  ')).toBe('example.com');
      expect(normalizeAssetValue('example.com.')).toBe('example.com');
      expect(normalizeAssetValue('[2001:4860:4860::8888]:443')).toBe('2001:4860:4860::8888');
    });
  });

  describe('validateAssetValue', () => {
    it('detecta dominios públicos', () => {
      expect(validateAssetValue('scanme.nmap.org')).toEqual({
        ok: true,
        type: AssetType.DOMAIN,
        value: 'scanme.nmap.org',
      });
    });

    it('detecta IPs públicas', () => {
      expect(validateAssetValue('45.33.32.156')).toEqual({
        ok: true,
        type: AssetType.IP,
        value: '45.33.32.156',
      });
    });

    it('rechaza IPs privadas y hosts no públicos', () => {
      expect(validateAssetValue('192.168.0.10').ok).toBe(false);
      expect(validateAssetValue('localhost').ok).toBe(false);
      expect(validateAssetValue('intranet.local').ok).toBe(false);
      expect(validateAssetValue('servidor').ok).toBe(false);
    });

    it('rechaza valores que no son dominio ni IP', () => {
      expect(validateAssetValue('esto no es un host').ok).toBe(false);
      expect(validateAssetValue('').ok).toBe(false);
    });

    it('en modo laboratorio acepta IPs privadas y hosts locales', () => {
      expect(validateAssetValue('127.0.0.1', undefined, { allowPrivate: true }).ok).toBe(true);
      expect(validateAssetValue('localhost', undefined, { allowPrivate: true }).ok).toBe(true);
      expect(validateAssetValue('no es host', undefined, { allowPrivate: true }).ok).toBe(false);
    });

    it('valida la coherencia con el tipo indicado', () => {
      expect(validateAssetValue('8.8.8.8', AssetType.DOMAIN).ok).toBe(false);
      expect(validateAssetValue('example.org', AssetType.IP).ok).toBe(false);
      expect(validateAssetValue('example.org', AssetType.DOMAIN).ok).toBe(true);
    });
  });
});
