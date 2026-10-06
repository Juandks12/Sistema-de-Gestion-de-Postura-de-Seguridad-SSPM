import { ConfigService } from '@nestjs/config';
import { KevSyncService } from './kev-sync.service';
import { KevCatalog, KevClient, KevSource } from './kev.client';

describe('CISA KEV Integration', () => {
  describe('KevClient', () => {
    let client: KevClient;
    let config: jest.Mocked<ConfigService>;
    const originalFetch = global.fetch;

    beforeEach(() => {
      config = {
        get: jest.fn().mockReturnValue('https://cisa.gov/mock-kev.json'),
      } as unknown as jest.Mocked<ConfigService>;
      client = new KevClient(config);
    });

    afterEach(() => {
      global.fetch = originalFetch;
    });

    it('descarga y parsea el catálogo CISA KEV correctamente', async () => {
      global.fetch = jest.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          title: 'CISA Catalog of Known Exploited Vulnerabilities',
          catalogVersion: '2026.09.29',
          dateReleased: '2026-09-29T13:51:33.3852Z',
          count: 2,
          vulnerabilities: [
            {
              cveID: 'cve-2026-86950',
              vendorProject: 'Apple',
              product: 'iOS',
              vulnerabilityName: 'Apple iOS Vulnerability',
              dateAdded: '2026-09-29',
              dueDate: '2026-10-02',
              knownRansomwareCampaignUse: 'Known',
            },
            {
              cveID: 'CVE-2021-44228',
              vendorProject: 'Apache',
              product: 'Log4j',
              vulnerabilityName: 'Apache Log4j RCE',
              dateAdded: '2021-12-10',
              dueDate: '2021-12-24',
              knownRansomwareCampaignUse: 'Known',
            },
          ],
        }),
      });

      const catalog = await client.fetchCatalog();

      expect(catalog.count).toBe(2);
      expect(catalog.catalogVersion).toBe('2026.09.29');
      expect(catalog.entries.has('CVE-2026-86950')).toBe(true);
      expect(catalog.entries.get('CVE-2026-86950')?.knownRansomwareCampaignUse).toBe('Known');
      expect(catalog.entries.has('CVE-2021-44228')).toBe(true);
    });

    it('lanza error si la API de CISA responde con error HTTP', async () => {
      global.fetch = jest.fn().mockResolvedValue({
        ok: false,
        status: 500,
      });

      await expect(client.fetchCatalog()).rejects.toThrow('CISA KEV respondió status HTTP 500');
    });
  });

  describe('KevSyncService', () => {
    let syncService: KevSyncService;
    let config: jest.Mocked<ConfigService>;
    let mockSource: jest.Mocked<KevSource>;

    beforeEach(() => {
      config = {
        get: jest.fn((key: string) => {
          if (key === 'CISA_KEV_SYNC_ENABLED') return true;
          if (key === 'CISA_KEV_CACHE_HOURS') return 24;
          return undefined;
        }),
      } as unknown as jest.Mocked<ConfigService>;

      mockSource = {
        fetchCatalog: jest.fn().mockResolvedValue({
          title: 'CISA Catalog',
          catalogVersion: '2026.1',
          dateReleased: '2026-01-01',
          count: 1,
          entries: new Map([
            [
              'CVE-2023-38408',
              {
                cveId: 'CVE-2023-38408',
                vulnerabilityName: 'OpenSSH RCE',
                dateAdded: '2023-08-01',
                dueDate: '2023-08-22',
                knownRansomwareCampaignUse: 'Unknown',
              },
            ],
          ]),
        } as KevCatalog),
      };

      syncService = new KevSyncService(config, mockSource);
    });

    it('sincroniza el catálogo y permite búsquedas O(1)', async () => {
      const count = await syncService.sync();
      expect(count).toBe(1);
      expect(syncService.isKev('CVE-2023-38408')).toBe(true);
      expect(syncService.isKev('cve-2023-38408')).toBe(true);
      expect(syncService.isKev('CVE-2099-0000')).toBe(false);

      const entry = syncService.get('CVE-2023-38408');
      expect(entry?.vulnerabilityName).toBe('OpenSSH RCE');
    });

    it('utiliza la caché y no vuelve a descargar si está vigente', async () => {
      await syncService.sync();
      await syncService.sync();

      expect(mockSource.fetchCatalog).toHaveBeenCalledTimes(1);
    });

    it('fuerza la descarga si se invoca con force = true', async () => {
      await syncService.sync();
      await syncService.sync(true);

      expect(mockSource.fetchCatalog).toHaveBeenCalledTimes(2);
    });
  });
});
