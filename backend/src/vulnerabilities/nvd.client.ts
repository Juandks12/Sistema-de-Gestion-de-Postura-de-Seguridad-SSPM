import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { CveEntry, NvdResponse, reduceNvdPage } from './cve-data';

/** Fuente de vulnerabilidades por producto. Se inyecta con `CVE_SOURCE` para sustituirla en las pruebas. */
export interface CveSource {
  productCves(vendor: string, product: string, signal: AbortSignal): Promise<{ total: number; entries: CveEntry[] }>;
}

export const CVE_SOURCE = Symbol('CVE_SOURCE');

export class CveSourceError extends Error {}

const PAGE_SIZE = 1000;
const MAX_PAGES = 10;
const REQUEST_TIMEOUT_MS = 60_000;

/**
 * Cliente de la API 2.0 de CVE de NVD. Descarga todos los CVE de un producto
 * (`virtualMatchString=cpe:2.3:a:vendor:product`) y la comprobación de la
 * versión concreta se hace localmente con los rangos de cada CVE, de modo que
 * una única descarga (cacheada) sirve para todas las versiones del producto.
 *
 * NVD limita a 5 peticiones cada 30 s sin clave y 50 con clave: las peticiones
 * de esta instancia se espacian en consecuencia.
 */
@Injectable()
export class NvdClient implements CveSource {
  private readonly logger = new Logger(NvdClient.name);
  private gate: Promise<void> = Promise.resolve();
  private lastRequestAt = 0;

  constructor(private readonly config: ConfigService) {}

  private get apiKey(): string {
    return this.config.get<string>('NVD_API_KEY')?.trim() ?? '';
  }

  private get intervalMs(): number {
    return this.apiKey ? 700 : 6500;
  }

  /** Espera su turno respetando el intervalo mínimo entre peticiones. */
  private async throttle(signal: AbortSignal): Promise<void> {
    const previous = this.gate;
    let release!: () => void;
    this.gate = new Promise((resolve) => (release = resolve));
    try {
      await previous;
      const wait = this.lastRequestAt + this.intervalMs - Date.now();
      if (wait > 0) await sleep(wait, signal);
      this.lastRequestAt = Date.now();
    } finally {
      release();
    }
  }

  async productCves(vendor: string, product: string, signal: AbortSignal): Promise<{ total: number; entries: CveEntry[] }> {
    const base = this.config.get<string>('NVD_API_URL') ?? 'https://services.nvd.nist.gov/rest/json/cves/2.0';
    const entries: CveEntry[] = [];
    let total = 0;
    for (let page = 0; page < MAX_PAGES; page += 1) {
      await this.throttle(signal);
      const startIndex = page * PAGE_SIZE;
      // noRejected es un parámetro sin valor en la API de NVD.
      const url =
        `${base}?virtualMatchString=${encodeURIComponent(`cpe:2.3:a:${vendor}:${product}`)}` +
        `&resultsPerPage=${PAGE_SIZE}&startIndex=${startIndex}&noRejected`;
      let body: NvdResponse;
      try {
        const res = await fetch(url, {
          headers: { accept: 'application/json', ...(this.apiKey ? { apiKey: this.apiKey } : {}) },
          signal: AbortSignal.any([signal, AbortSignal.timeout(REQUEST_TIMEOUT_MS)]),
        });
        if (!res.ok) {
          throw new CveSourceError(`NVD respondió ${res.status}${res.status === 403 || res.status === 429 ? ' (límite de peticiones)' : ''}`);
        }
        body = (await res.json()) as NvdResponse;
      } catch (err) {
        if (signal.aborted) throw err;
        if (err instanceof CveSourceError) throw err;
        throw new CveSourceError(`No se pudo consultar NVD: ${(err as Error).message}`);
      }
      total = body.totalResults ?? 0;
      entries.push(...reduceNvdPage(body, vendor, product));
      if (startIndex + PAGE_SIZE >= total) break;
      if (page === MAX_PAGES - 1) {
        this.logger.warn(`NVD: ${vendor}:${product} tiene ${total} CVE; se procesan los primeros ${MAX_PAGES * PAGE_SIZE}`);
      }
    }
    return { total, entries };
  }
}

function sleep(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal.aborted) return reject(new Error('aborted'));
    const timer = setTimeout(() => {
      signal.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    const onAbort = () => {
      clearTimeout(timer);
      reject(new Error('aborted'));
    };
    signal.addEventListener('abort', onAbort, { once: true });
  });
}
