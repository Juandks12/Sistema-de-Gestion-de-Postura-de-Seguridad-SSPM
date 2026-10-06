import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

export interface EpssScore {
  cve: string;
  epss: number;
  percentile: number;
  date?: string;
}

export interface EpssSource {
  scores(cves: string[], signal: AbortSignal): Promise<Map<string, EpssScore>>;
}

export const EPSS_SOURCE = Symbol('EPSS_SOURCE');

export class EpssSourceError extends Error {}

interface EpssApiItem {
  cve: string;
  epss: string;
  percentile: string;
  date?: string;
}

interface EpssApiResponse {
  status: string;
  'status-code': number;
  data?: EpssApiItem[];
}

const DEFAULT_EPSS_API_URL = 'https://api.first.org/data/v1/epss';
const CHUNK_SIZE = 100;
const REQUEST_TIMEOUT_MS = 15_000;

/**
 * Cliente de la API de FIRST EPSS (Exploit Prediction Scoring System).
 *
 * Consulta la probabilidad de explotación en ataques reales (0.0 a 1.0)
 * y el percentil de riesgo para una lista de identificadores CVE.
 * Permite consultas por lotes de hasta 100 CVEs por petición.
 */
@Injectable()
export class EpssClient implements EpssSource {
  private readonly logger = new Logger(EpssClient.name);

  constructor(private readonly config: ConfigService) {}

  private get apiUrl(): string {
    return this.config.get<string>('EPSS_API_URL')?.trim() || DEFAULT_EPSS_API_URL;
  }

  async scores(cves: string[], signal: AbortSignal): Promise<Map<string, EpssScore>> {
    const result = new Map<string, EpssScore>();
    const cleanCves = [...new Set(cves.map((c) => c.trim().toUpperCase()))].filter(Boolean);

    if (cleanCves.length === 0) return result;

    for (let i = 0; i < cleanCves.length; i += CHUNK_SIZE) {
      if (signal.aborted) break;

      const chunk = cleanCves.slice(i, i + CHUNK_SIZE);
      const url = `${this.apiUrl}?cve=${chunk.map(encodeURIComponent).join(',')}`;

      try {
        const res = await fetch(url, {
          headers: { accept: 'application/json', 'user-agent': 'SSPM-SaaS-Lite (EPSS client)' },
          signal: AbortSignal.any([signal, AbortSignal.timeout(REQUEST_TIMEOUT_MS)]),
        });

        if (!res.ok) {
          this.logger.warn(`EPSS API respondió status ${res.status} para lote de ${chunk.length} CVEs`);
          continue;
        }

        const body = (await res.json()) as EpssApiResponse;
        if (body.data && Array.isArray(body.data)) {
          for (const item of body.data) {
            const epss = parseFloat(item.epss);
            const percentile = parseFloat(item.percentile);
            if (!Number.isNaN(epss) && !Number.isNaN(percentile)) {
              result.set(item.cve.toUpperCase(), {
                cve: item.cve.toUpperCase(),
                epss,
                percentile,
                date: item.date,
              });
            }
          }
        }
      } catch (err) {
        if (signal.aborted) throw err;
        this.logger.warn(`Error consultando EPSS para ${chunk.length} CVEs: ${(err as Error).message}`);
      }
    }

    return result;
  }
}
