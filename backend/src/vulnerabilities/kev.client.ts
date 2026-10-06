import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

export interface KevEntry {
  cveId: string;
  vendorProject?: string;
  product?: string;
  vulnerabilityName: string;
  dateAdded: string;
  dueDate: string | null;
  knownRansomwareCampaignUse: 'Known' | 'Unknown';
  shortDescription?: string;
  requiredAction?: string;
  notes?: string;
}

export interface KevCatalog {
  title: string;
  catalogVersion: string;
  dateReleased: string;
  count: number;
  entries: Map<string, KevEntry>;
}

export interface KevSource {
  fetchCatalog(signal?: AbortSignal): Promise<KevCatalog>;
}

export const KEV_SOURCE = Symbol('KEV_SOURCE');

export class KevSourceError extends Error {}

interface CisaKevApiItem {
  cveID: string;
  vendorProject?: string;
  product?: string;
  vulnerabilityName?: string;
  dateAdded?: string;
  dueDate?: string;
  knownRansomwareCampaignUse?: string;
  shortDescription?: string;
  requiredAction?: string;
  notes?: string;
}

interface CisaKevApiResponse {
  title?: string;
  catalogVersion?: string;
  dateReleased?: string;
  count?: number;
  vulnerabilities?: CisaKevApiItem[];
}

export const DEFAULT_CISA_KEV_URL =
  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const REQUEST_TIMEOUT_MS = 30_000;

/**
 * Cliente HTTP para el catálogo oficial CISA KEV (Known Exploited Vulnerabilities).
 *
 * Descarga y parsea el feed oficial de vulnerabilidades con explotación activa conocida
 * por cibercriminales y campañas de ransomware.
 */
@Injectable()
export class KevClient implements KevSource {
  private readonly logger = new Logger(KevClient.name);

  constructor(private readonly config: ConfigService) {}

  private get catalogUrl(): string {
    return this.config.get<string>('CISA_KEV_URL')?.trim() || DEFAULT_CISA_KEV_URL;
  }

  async fetchCatalog(signal?: AbortSignal): Promise<KevCatalog> {
    const url = this.catalogUrl;
    try {
      const res = await fetch(url, {
        headers: { accept: 'application/json', 'user-agent': 'SSPM-SaaS-Lite (CISA KEV Client)' },
        signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(REQUEST_TIMEOUT_MS)]) : AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });

      if (!res.ok) {
        throw new KevSourceError(`CISA KEV respondió status HTTP ${res.status}`);
      }

      const body = (await res.json()) as CisaKevApiResponse;
      const entries = new Map<string, KevEntry>();

      for (const item of body.vulnerabilities ?? []) {
        if (!item.cveID) continue;
        const cveId = item.cveID.trim().toUpperCase();
        entries.set(cveId, {
          cveId,
          vendorProject: item.vendorProject,
          product: item.product,
          vulnerabilityName: item.vulnerabilityName || 'Known Exploited Vulnerability',
          dateAdded: item.dateAdded || new Date().toISOString().slice(0, 10),
          dueDate: item.dueDate || null,
          knownRansomwareCampaignUse: item.knownRansomwareCampaignUse === 'Known' ? 'Known' : 'Unknown',
          shortDescription: item.shortDescription,
          requiredAction: item.requiredAction,
          notes: item.notes,
        });
      }

      return {
        title: body.title || 'CISA Catalog of Known Exploited Vulnerabilities',
        catalogVersion: body.catalogVersion || 'unknown',
        dateReleased: body.dateReleased || new Date().toISOString(),
        count: entries.size,
        entries,
      };
    } catch (err) {
      if (signal?.aborted) throw err;
      if (err instanceof KevSourceError) throw err;
      throw new KevSourceError(`Error descargando catálogo CISA KEV: ${(err as Error).message}`);
    }
  }
}
