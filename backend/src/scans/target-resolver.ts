import { AssetType } from '@prisma/client';
import type { LookupAddress } from 'node:dns';
import { lookup as dnsLookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import { isPrivateOrReservedIp } from '../common/utils/network.util';
import { ScanExecutionError } from './scan.errors';

export interface ResolvedTarget {
  address: string;
  family: 4 | 6;
  /** Todas las direcciones a las que resolvió el dominio (informativo). */
  resolvedAddresses: string[];
}

export type LookupFn = (hostname: string, options: { all: true; verbatim: boolean }) => Promise<LookupAddress[]>;

export interface ResolveTargetOptions {
  skipCache?: boolean;
  ttlMs?: number;
  maxRetries?: number;
}

interface CacheEntry {
  target: ResolvedTarget;
  expiresAt: number;
}

const dnsCache = new Map<string, CacheEntry>();
const DEFAULT_DNS_CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutos de TTL por defecto
const MAX_CACHE_ENTRIES = 1000;

export function clearDnsCache(): void {
  dnsCache.clear();
}

export function getDnsCacheSize(): number {
  return dnsCache.size;
}

function pruneCacheIfNeeded(): void {
  if (dnsCache.size < MAX_CACHE_ENTRIES) return;
  const now = Date.now();
  for (const [k, v] of dnsCache) {
    if (v.expiresAt <= now) {
      dnsCache.delete(k);
    }
  }
  if (dnsCache.size >= MAX_CACHE_ENTRIES) {
    const toDelete = dnsCache.size - Math.floor(MAX_CACHE_ENTRIES * 0.8);
    let deleted = 0;
    for (const k of dnsCache.keys()) {
      dnsCache.delete(k);
      deleted++;
      if (deleted >= toDelete) break;
    }
  }
}

const TRANSIENT_DNS_CODES = new Set([
  'ETIMEDOUT',
  'ESERVFAIL',
  'EAI_AGAIN',
  'ECONNREFUSED',
  'ECONNRESET',
  'EBUSY',
]);

function isTransientDnsError(err: unknown): boolean {
  if (!err || typeof err !== 'object') return false;
  const code = (err as { code?: string }).code;
  if (code && TRANSIENT_DNS_CODES.has(code)) return true;
  const message = (err as Error).message ?? '';
  return /timeout|servfail|eai_again|try again|timed out/i.test(message);
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Resuelve el activo a una IP concreta justo antes del escaneo con caché en memoria y reintentos.
 *
 * Protección contra abuso del escáner (sección 11.3): un dominio registrado como
 * público podría apuntar después (o mediante DNS rebinding) a una red interna.
 * Si alguna dirección resuelta es privada/reservada se bloquea el escaneo, y a
 * Nmap se le entrega la IP ya validada para evitar una segunda resolución (TOCTOU).
 *
 * Incluye aceleración de caché DNS con TTL y reintentos con backoff exponencial
 * para tolerar fallas de red y servidores DNS intermitentes.
 */
export async function resolveScanTarget(
  value: string,
  type: AssetType,
  allowPrivate: boolean,
  lookup: LookupFn = dnsLookup as LookupFn,
  options?: ResolveTargetOptions,
): Promise<ResolvedTarget> {
  const cleanValue = value.trim();
  const cacheKey = `${cleanValue.toLowerCase()}:${allowPrivate ? 'priv' : 'pub'}`;
  const now = Date.now();

  if (!options?.skipCache) {
    const cached = dnsCache.get(cacheKey);
    if (cached && cached.expiresAt > now) {
      return cached.target;
    }
  }

  if (type === AssetType.IP) {
    const family = isIP(cleanValue);
    if (family === 0) {
      throw new ScanExecutionError(`La dirección IP ${value} no es válida`);
    }
    if (!allowPrivate && isPrivateOrReservedIp(cleanValue)) {
      throw new ScanExecutionError(`La IP ${value} es privada o reservada; escaneo bloqueado`);
    }
    const result: ResolvedTarget = { address: cleanValue, family: family as 4 | 6, resolvedAddresses: [cleanValue] };
    if (!options?.skipCache) {
      pruneCacheIfNeeded();
      dnsCache.set(cacheKey, {
        target: result,
        expiresAt: now + (options?.ttlMs ?? DEFAULT_DNS_CACHE_TTL_MS),
      });
    }
    return result;
  }

  const maxRetries = options?.maxRetries ?? 2;
  let addresses: LookupAddress[] | undefined;

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      addresses = await lookup(cleanValue, { all: true, verbatim: true });
      break;
    } catch (err) {
      if (attempt < maxRetries && isTransientDnsError(err)) {
        const delay = 50 * Math.pow(2, attempt) + Math.floor(Math.random() * 25);
        await sleep(delay);
        continue;
      }
      throw new ScanExecutionError(`No se pudo resolver el dominio ${value}`);
    }
  }

  if (!addresses || addresses.length === 0) {
    throw new ScanExecutionError(`El dominio ${value} no tiene registros DNS A/AAAA`);
  }

  if (!allowPrivate) {
    const blocked = addresses.find((a) => isPrivateOrReservedIp(a.address));
    if (blocked) {
      throw new ScanExecutionError(
        `El dominio ${value} resuelve a una dirección privada o reservada (${blocked.address}); escaneo bloqueado`,
      );
    }
  }

  const chosen = addresses.find((a) => a.family === 4) ?? addresses[0];
  const result: ResolvedTarget = {
    address: chosen.address,
    family: chosen.family as 4 | 6,
    resolvedAddresses: addresses.map((a) => a.address),
  };

  if (!options?.skipCache) {
    pruneCacheIfNeeded();
    dnsCache.set(cacheKey, {
      target: result,
      expiresAt: now + (options?.ttlMs ?? DEFAULT_DNS_CACHE_TTL_MS),
    });
  }

  return result;
}
