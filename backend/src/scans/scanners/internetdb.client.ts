import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { isIP } from 'node:net';

export interface InternetDbData {
  ip: string;
  ports: number[];
  cpes: string[];
  hostnames: string[];
  tags: string[];
  vulns: string[];
}

export interface InternetDbSource {
  get(ip: string, signal?: AbortSignal, options?: InternetDbQueryOptions): Promise<InternetDbData | null>;
}

export interface InternetDbQueryOptions {
  skipCache?: boolean;
  retries?: number;
}

export const INTERNETDB_SOURCE = Symbol('INTERNETDB_SOURCE');

export class InternetDbError extends Error {}

const DEFAULT_INTERNETDB_URL = 'https://internetdb.shodan.io';
const DEFAULT_TIMEOUT_MS = 5_000;
const DEFAULT_CACHE_TTL_MS = 15 * 60 * 1000; // 15 minutos para respuestas exitosas
const DEFAULT_NEGATIVE_CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutos para 404 (no indexado)
const MAX_CACHE_ENTRIES = 2_000;
const DEFAULT_MAX_RETRIES = 2;

interface CacheEntry {
  data: InternetDbData | null;
  expiresAt: number;
}

const internetDbCache = new Map<string, CacheEntry>();

export function clearInternetDbCache(): void {
  internetDbCache.clear();
}

export function getInternetDbCacheSize(): number {
  return internetDbCache.size;
}

function pruneCacheIfNeeded(): void {
  if (internetDbCache.size < MAX_CACHE_ENTRIES) return;
  const now = Date.now();
  for (const [k, v] of internetDbCache) {
    if (v.expiresAt <= now) {
      internetDbCache.delete(k);
    }
  }
  if (internetDbCache.size >= MAX_CACHE_ENTRIES) {
    const toDelete = internetDbCache.size - Math.floor(MAX_CACHE_ENTRIES * 0.8);
    let deleted = 0;
    for (const k of internetDbCache.keys()) {
      internetDbCache.delete(k);
      deleted++;
      if (deleted >= toDelete) break;
    }
  }
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Cliente resiliente para Shodan InternetDB (https://internetdb.shodan.io).
 *
 * API pública, gratuita y sin requerimiento de API key diseñada para
 * reconocimiento pasivo ultrarrápido (<300 ms).
 * Permite conocer puertos abiertos, CPEs detectados, hostnames, vulnerabilidades
 * y etiquetas de red sin enviar tráfico directo al objetivo.
 *
 * Incluye:
 * - Caché en memoria con TTL positivo (15 min) y negativo (5 min para 404).
 * - Reintentos con backoff exponencial y jitter ante respuestas 429/5xx o caídas transitorias de red.
 */
@Injectable()
export class InternetDbClient implements InternetDbSource {
  private readonly logger = new Logger(InternetDbClient.name);

  constructor(private readonly config: ConfigService) {}

  clearCache(): void {
    clearInternetDbCache();
  }

  private get baseUrl(): string {
    return this.config.get<string>('SHODAN_INTERNETDB_URL')?.trim().replace(/\/+$/, '') || DEFAULT_INTERNETDB_URL;
  }

  private get timeoutMs(): number {
    return this.config.get<number>('SHODAN_INTERNETDB_TIMEOUT_MS') ?? DEFAULT_TIMEOUT_MS;
  }

  private get cacheTtlMs(): number {
    return this.config.get<number>('SHODAN_INTERNETDB_CACHE_TTL_MS') ?? DEFAULT_CACHE_TTL_MS;
  }

  private get maxRetries(): number {
    return this.config.get<number>('SHODAN_INTERNETDB_MAX_RETRIES') ?? DEFAULT_MAX_RETRIES;
  }

  /**
   * Obtiene la información pasiva indexada por Shodan para una dirección IP.
   * Retorna `null` si la IP no tiene registros públicos en Shodan (HTTP 404) o si no es una IP válida.
   */
  async get(ip: string, signal?: AbortSignal, options?: InternetDbQueryOptions): Promise<InternetDbData | null> {
    const cleanIp = ip.trim();
    if (!isIP(cleanIp)) {
      this.logger.debug(`Valor proporcionado no es una IP válida para InternetDB: "${ip}"`);
      return null;
    }

    const now = Date.now();
    if (!options?.skipCache) {
      const cached = internetDbCache.get(cleanIp);
      if (cached && cached.expiresAt > now) {
        return cached.data;
      }
    }

    const url = `${this.baseUrl}/${encodeURIComponent(cleanIp)}`;
    const retries = options?.retries ?? this.maxRetries;

    for (let attempt = 0; attempt <= retries; attempt++) {
      if (signal?.aborted) {
        throw new Error('Consulta a InternetDB abortada por señal');
      }

      try {
        const abortSignals = [AbortSignal.timeout(this.timeoutMs)];
        if (signal) {
          abortSignals.push(signal);
        }

        const res = await fetch(url, {
          headers: {
            accept: 'application/json',
            'user-agent': 'SSPM-SaaS-Lite (Shodan InternetDB client)',
          },
          signal: AbortSignal.any(abortSignals),
        });

        if (res.status === 404) {
          // Shodan no tiene puertos u observaciones registradas para esta IP.
          if (!options?.skipCache) {
            pruneCacheIfNeeded();
            internetDbCache.set(cleanIp, {
              data: null,
              expiresAt: now + DEFAULT_NEGATIVE_CACHE_TTL_MS,
            });
          }
          return null;
        }

        if (res.status === 429 || (res.status >= 500 && res.status <= 599)) {
          if (attempt < retries) {
            const delay = 100 * Math.pow(2, attempt) + Math.floor(Math.random() * 50);
            this.logger.warn(
              `Shodan InternetDB respondió HTTP ${res.status} para ${cleanIp}. Reintentando en ${delay}ms (intento ${attempt + 1}/${retries})...`,
            );
            await sleep(delay);
            continue;
          }
          this.logger.warn(`Shodan InternetDB respondió status ${res.status} para IP ${cleanIp} tras agotar reintentos`);
          return null;
        }

        if (!res.ok) {
          this.logger.warn(`Shodan InternetDB respondió status inesperado ${res.status} para IP ${cleanIp}`);
          return null;
        }

        const data = (await res.json()) as Partial<InternetDbData>;
        const result: InternetDbData = {
          ip: data.ip || cleanIp,
          ports: Array.isArray(data.ports) ? data.ports.filter((p): p is number => typeof p === 'number') : [],
          cpes: Array.isArray(data.cpes) ? data.cpes.filter((c): c is string => typeof c === 'string') : [],
          hostnames: Array.isArray(data.hostnames) ? data.hostnames.filter((h): h is string => typeof h === 'string') : [],
          tags: Array.isArray(data.tags) ? data.tags.filter((t): t is string => typeof t === 'string') : [],
          vulns: Array.isArray(data.vulns) ? data.vulns.filter((v): v is string => typeof v === 'string') : [],
        };

        if (!options?.skipCache) {
          pruneCacheIfNeeded();
          internetDbCache.set(cleanIp, {
            data: result,
            expiresAt: now + this.cacheTtlMs,
          });
        }

        return result;
      } catch (err) {
        if (signal?.aborted) throw err;
        if (attempt < retries) {
          const delay = 100 * Math.pow(2, attempt) + Math.floor(Math.random() * 50);
          this.logger.warn(
            `Fallo de conexión consultando InternetDB para ${cleanIp}: ${(err as Error).message}. Reintentando en ${delay}ms...`,
          );
          await sleep(delay);
          continue;
        }
        this.logger.warn(`Error al consultar Shodan InternetDB para ${cleanIp}: ${(err as Error).message}`);
        return null;
      }
    }

    return null;
  }
}
