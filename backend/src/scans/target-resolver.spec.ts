import { AssetType } from '@prisma/client';
import { ScanExecutionError } from './scan.errors';
import { clearDnsCache, getDnsCacheSize, LookupFn, resolveScanTarget } from './target-resolver';

const fakeLookup =
  (addresses: Array<{ address: string; family: number }>): LookupFn =>
  async () =>
    addresses;

describe('resolveScanTarget', () => {
  beforeEach(() => {
    clearDnsCache();
  });

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

  it('reutiliza la caché DNS para evitar resoluciones repetidas', async () => {
    const lookup = jest.fn().mockResolvedValue([
      { address: '93.184.216.34', family: 4 },
    ]);

    const first = await resolveScanTarget('cached.example.org', AssetType.DOMAIN, false, lookup);
    expect(first.address).toBe('93.184.216.34');
    expect(lookup).toHaveBeenCalledTimes(1);

    const second = await resolveScanTarget('cached.example.org', AssetType.DOMAIN, false, lookup);
    expect(second.address).toBe('93.184.216.34');
    expect(lookup).toHaveBeenCalledTimes(1); // No volvió a llamar a lookup

    expect(getDnsCacheSize()).toBeGreaterThanOrEqual(1);
  });

  it('permite omitir la caché explícitamente con skipCache', async () => {
    const lookup = jest.fn().mockResolvedValue([
      { address: '93.184.216.34', family: 4 },
    ]);

    await resolveScanTarget('cached.example.org', AssetType.DOMAIN, false, lookup);
    expect(lookup).toHaveBeenCalledTimes(1);

    await resolveScanTarget('cached.example.org', AssetType.DOMAIN, false, lookup, { skipCache: true });
    expect(lookup).toHaveBeenCalledTimes(2);
  });

  it('reintenta con backoff ante errores de DNS transitorios y tiene éxito', async () => {
    let callCount = 0;
    const lookup: LookupFn = async () => {
      callCount++;
      if (callCount === 1) {
        throw Object.assign(new Error('getaddrinfo EAI_AGAIN'), { code: 'EAI_AGAIN' });
      }
      return [{ address: '93.184.216.34', family: 4 }];
    };

    const target = await resolveScanTarget('transient.example.org', AssetType.DOMAIN, false, lookup, {
      maxRetries: 2,
    });
    expect(target.address).toBe('93.184.216.34');
    expect(callCount).toBe(2);
  });

  it('falla si los reintentos transitorios se agotan', async () => {
    let callCount = 0;
    const lookup: LookupFn = async () => {
      callCount++;
      throw Object.assign(new Error('queryA ETIMEDOUT'), { code: 'ETIMEDOUT' });
    };

    await expect(
      resolveScanTarget('timeout.example.org', AssetType.DOMAIN, false, lookup, {
        maxRetries: 1,
      }),
    ).rejects.toThrow(/No se pudo resolver el dominio/);
    expect(callCount).toBe(2);
  });

  it('expira entradas de caché según el TTL', async () => {
    const lookup = jest.fn().mockResolvedValue([
      { address: '1.2.3.4', family: 4 },
    ]);

    await resolveScanTarget('ttl.example.org', AssetType.DOMAIN, false, lookup, { ttlMs: 10 });
    expect(lookup).toHaveBeenCalledTimes(1);

    // Esperar a que expire el TTL
    await new Promise((resolve) => setTimeout(resolve, 20));

    await resolveScanTarget('ttl.example.org', AssetType.DOMAIN, false, lookup, { ttlMs: 10 });
    expect(lookup).toHaveBeenCalledTimes(2);
  });
});
