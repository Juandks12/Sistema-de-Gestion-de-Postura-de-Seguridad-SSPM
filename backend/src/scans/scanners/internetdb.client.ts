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
  get(ip: string, signal?: AbortSignal): Promise<InternetDbData | null>;
}

export const INTERNETDB_SOURCE = Symbol('INTERNETDB_SOURCE');

export class InternetDbError extends Error {}

const DEFAULT_INTERNETDB_URL = 'https://internetdb.shodan.io';
const DEFAULT_TIMEOUT_MS = 5_000;

/**
 * Cliente para Shodan InternetDB (https://internetdb.shodan.io).
 *
 * API pública, gratuita y sin requerimiento de API key diseñada para
 * reconocimiento pasivo ultrarrápido (<300 ms).
 * Permite conocer puertos abiertos, CPEs detectados, hostnames, vulnerabilidades
 * y etiquetas de red sin enviar tráfico directo al objetivo.
 */
@Injectable()
export class InternetDbClient implements InternetDbSource {
  private readonly logger = new Logger(InternetDbClient.name);

  constructor(private readonly config: ConfigService) {}

  private get baseUrl(): string {
    return this.config.get<string>('SHODAN_INTERNETDB_URL')?.trim().replace(/\/+$/, '') || DEFAULT_INTERNETDB_URL;
  }

  private get timeoutMs(): number {
    return this.config.get<number>('SHODAN_INTERNETDB_TIMEOUT_MS') ?? DEFAULT_TIMEOUT_MS;
  }

  /**
   * Obtiene la información pasiva indexada por Shodan para una dirección IP.
   * Retorna `null` si la IP no tiene registros públicos en Shodan (HTTP 404) o si no es una IP válida.
   */
  async get(ip: string, signal?: AbortSignal): Promise<InternetDbData | null> {
    const cleanIp = ip.trim();
    if (!isIP(cleanIp)) {
      this.logger.debug(`Valor proporcionado no es una IP válida para InternetDB: "${ip}"`);
      return null;
    }

    const url = `${this.baseUrl}/${encodeURIComponent(cleanIp)}`;

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
        return null;
      }

      if (!res.ok) {
        this.logger.warn(`Shodan InternetDB respondió status ${res.status} para IP ${cleanIp}`);
        return null;
      }

      const data = (await res.json()) as Partial<InternetDbData>;
      return {
        ip: data.ip || cleanIp,
        ports: Array.isArray(data.ports) ? data.ports.filter((p): p is number => typeof p === 'number') : [],
        cpes: Array.isArray(data.cpes) ? data.cpes.filter((c): c is string => typeof c === 'string') : [],
        hostnames: Array.isArray(data.hostnames) ? data.hostnames.filter((h): h is string => typeof h === 'string') : [],
        tags: Array.isArray(data.tags) ? data.tags.filter((t): t is string => typeof t === 'string') : [],
        vulns: Array.isArray(data.vulns) ? data.vulns.filter((v): v is string => typeof v === 'string') : [],
      };
    } catch (err) {
      if (signal?.aborted) throw err;
      this.logger.warn(`Error al consultar Shodan InternetDB para ${cleanIp}: ${(err as Error).message}`);
      return null;
    }
  }
}
