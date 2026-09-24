import { AssetType } from '@prisma/client';
import { ScanExecutionError } from './scan.errors';
import { LookupFn, resolveScanTarget } from './target-resolver';

const fakeLookup =
  (addresses: Array<{ address: string; family: number }>): LookupFn =>
  async () =>
    addresses;

describe('resolveScanTarget', () => {
  it('devuelve directamente las IP públicas', async () => {
    await expect(resolveScanTarget('45.33.32.156', AssetType.IP, false)).resolves.toMatchObject({
      address: '45.33.32.156',
      family: 4,
    });
  });

  it('bloquea IP privadas salvo en modo laboratorio', async () => {
    await expect(resolveScanTarget('10.0.0.1', AssetType.IP, false)).rejects.toBeInstanceOf(
      ScanExecutionError,
    );
    await expect(resolveScanTarget('10.0.0.1', AssetType.IP, true)).resolves.toMatchObject({
      address: '10.0.0.1',
    });
  });

  it('resuelve dominios prefiriendo IPv4', async () => {
    const lookup = fakeLookup([
      { address: '2606:4700::1', family: 6 },
      { address: '104.16.1.1', family: 4 },
    ]);
    await expect(
      resolveScanTarget('example.org', AssetType.DOMAIN, false, lookup),
    ).resolves.toEqual({
      address: '104.16.1.1',
      family: 4,
      resolvedAddresses: ['2606:4700::1', '104.16.1.1'],
    });
  });

  it('bloquea dominios que resuelven a redes internas (DNS rebinding / SSRF)', async () => {
    const lookup = fakeLookup([
      { address: '104.16.1.1', family: 4 },
      { address: '192.168.1.20', family: 4 },
    ]);
    await expect(
      resolveScanTarget('evil.example.org', AssetType.DOMAIN, false, lookup),
    ).rejects.toThrow(/privada o reservada/);
  });

  it('informa cuando el dominio no se puede resolver', async () => {
    const failing: LookupFn = async () => {
      throw new Error('ENOTFOUND');
    };
    await expect(
      resolveScanTarget('noexiste.example.org', AssetType.DOMAIN, false, failing),
    ).rejects.toThrow(/No se pudo resolver/);
  });
});
