import { AssetType } from '../generated/prisma/client';
import { InvalidTargetError, isPublicIp, normalizeTarget } from './asset-target.util';

describe('normalizeTarget', () => {
  it('normaliza dominios a minúsculas y sin punto final', () => {
    expect(normalizeTarget('  WWW.Acme.COM. ')).toEqual({
      type: AssetType.DOMAIN,
      value: 'www.acme.com',
    });
  });

  it('clasifica IPs públicas v4 y v6', () => {
    expect(normalizeTarget('8.8.8.8')).toEqual({ type: AssetType.IP, value: '8.8.8.8' });
    expect(normalizeTarget('[2606:4700::1111]')).toEqual({
      type: AssetType.IP,
      value: '2606:4700::1111',
    });
  });

  it.each(['10.0.0.5', '192.168.1.10', '172.20.3.4', '127.0.0.1', '169.254.1.1', '::1', 'fd00::1'])(
    'rechaza la IP privada/reservada %s por defecto',
    (ip) => {
      expect(() => normalizeTarget(ip)).toThrow(InvalidTargetError);
    },
  );

  it('permite IPs privadas cuando allowPrivate es true', () => {
    expect(normalizeTarget('192.168.1.10', { allowPrivate: true })).toEqual({
      type: AssetType.IP,
      value: '192.168.1.10',
    });
  });

  it.each([
    'https://acme.com',
    'acme.com/login',
    'acme.com:8080',
    'localhost',
    'server.local',
    'acme',
    '-bad-.com',
    '',
  ])('rechaza el valor inválido %p', (value) => {
    expect(() => normalizeTarget(value)).toThrow(InvalidTargetError);
  });
});

describe('isPublicIp', () => {
  it('detecta rangos de documentación y CGNAT como no públicos', () => {
    expect(isPublicIp('203.0.113.7')).toBe(false);
    expect(isPublicIp('100.64.0.1')).toBe(false);
    expect(isPublicIp('2001:db8::1')).toBe(false);
    expect(isPublicIp('::ffff:10.0.0.1')).toBe(false);
  });

  it('acepta IPs públicas', () => {
    expect(isPublicIp('1.1.1.1')).toBe(true);
    expect(isPublicIp('2a00:1450:4003:80b::200e')).toBe(true);
  });
});
