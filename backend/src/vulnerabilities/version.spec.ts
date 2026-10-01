import { compareVersions } from './version';

const sign = (a: string, b: string) => Math.sign(compareVersions(a, b));

describe('compareVersions', () => {
  it('compara segmentos numéricos', () => {
    expect(sign('2.4.29', '2.4.30')).toBe(-1);
    expect(sign('2.4.100', '2.4.29')).toBe(1);
    expect(sign('1.14.0', '1.14.0')).toBe(0);
    expect(sign('1.2', '1.2.0')).toBe(0);
    expect(sign('10.0', '9.9.9')).toBe(1);
  });

  it('trata las letras de OpenSSL como versiones posteriores', () => {
    expect(sign('1.0.2', '1.0.2k')).toBe(-1);
    expect(sign('1.0.2k', '1.0.2l')).toBe(-1);
    expect(sign('1.1.1w', '1.1.1')).toBe(1);
  });

  it('considera anteriores las versiones de pre-lanzamiento', () => {
    expect(sign('5.7.0-rc1', '5.7.0')).toBe(-1);
    expect(sign('2.0.0-beta2', '2.0.0-beta10')).toBe(-1);
    expect(sign('2.0.0-beta', '2.0.0-rc1')).toBe(-1);
  });

  it('el sufijo pN de OpenSSH portable es la misma versión', () => {
    expect(sign('7.4p1', '7.4')).toBe(0);
    expect(sign('7.4p1', '7.4p2')).toBe(-1);
    expect(sign('8.2p1', '8.5')).toBe(-1);
    expect(sign('9.3p2', '9.3')).toBe(0);
  });
});
