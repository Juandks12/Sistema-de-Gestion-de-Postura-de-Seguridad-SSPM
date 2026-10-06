import { Inject, Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { KEV_SOURCE, KevCatalog, KevEntry, KevSource } from './kev.client';

/**
 * Servicio sincronizador y de consulta del catálogo CISA KEV (Known Exploited Vulnerabilities).
 *
 * Mantiene en memoria el catálogo de vulnerabilidades con explotación activa conocida
 * con refresco periódico y caché configurable.
 */
@Injectable()
export class KevSyncService implements OnModuleInit {
  private readonly logger = new Logger(KevSyncService.name);
  private catalog: KevCatalog | null = null;
  private lastFetchedAt: Date | null = null;
  private syncPromise: Promise<number> | null = null;

  constructor(
    private readonly config: ConfigService,
    @Inject(KEV_SOURCE) private readonly source: KevSource,
  ) {}

  async onModuleInit(): Promise<void> {
    if (this.enabled) {
      // Sincronización en segundo plano al iniciar para tener la caché lista
      this.sync().catch((err) => {
        this.logger.warn(`Sincronización inicial CISA KEV falló: ${(err as Error).message}`);
      });
    }
  }

  get enabled(): boolean {
    return this.config.get<boolean>('CISA_KEV_SYNC_ENABLED') !== false;
  }

  private get cacheMs(): number {
    const hours = this.config.get<number>('CISA_KEV_CACHE_HOURS') ?? 24;
    return hours * 60 * 60 * 1000;
  }

  get isCacheValid(): boolean {
    if (!this.catalog || !this.lastFetchedAt) return false;
    return Date.now() - this.lastFetchedAt.getTime() < this.cacheMs;
  }

  get count(): number {
    return this.catalog?.entries.size ?? 0;
  }

  get version(): string | null {
    return this.catalog?.catalogVersion ?? null;
  }

  async sync(force = false, signal?: AbortSignal): Promise<number> {
    if (!this.enabled) return 0;
    if (!force && this.isCacheValid) {
      return this.count;
    }

    if (this.syncPromise) {
      return this.syncPromise;
    }

    this.syncPromise = (async () => {
      try {
        this.logger.log('Sincronizando catálogo oficial CISA KEV...');
        const newCatalog = await this.source.fetchCatalog(signal);
        this.catalog = newCatalog;
        this.lastFetchedAt = new Date();
        this.logger.log(
          `CISA KEV sincronizado exitosamente: ${newCatalog.count} vulnerabilidades (versión ${newCatalog.catalogVersion})`,
        );
        return newCatalog.count;
      } catch (err) {
        if (signal?.aborted) throw err;
        this.logger.warn(`Error sincronizando CISA KEV: ${(err as Error).message}`);
        return this.count;
      } finally {
        this.syncPromise = null;
      }
    })();

    return this.syncPromise;
  }

  get(cveId: string): KevEntry | null {
    if (!this.catalog || !cveId) return null;
    return this.catalog.entries.get(cveId.trim().toUpperCase()) ?? null;
  }

  isKev(cveId: string): boolean {
    return this.get(cveId) !== null;
  }
}
