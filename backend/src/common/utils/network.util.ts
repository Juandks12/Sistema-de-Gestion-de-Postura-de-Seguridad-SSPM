import { AssetType } from '@prisma/client';
import { isFQDN, isIP } from 'class-validator';

/**
 * Utilidades para validar y normalizar activos externos (RF-01).
 * El sistema solo analiza activos públicos (sección 1.5/1.6 del documento),
 * por lo que se rechazan direcciones privadas, de loopback y reservadas.
 */

const PRIVATE_IPV4_RANGES: Array<[string, number]> = [
  ['0.0.0.0', 8], // "this" network
  ['10.0.0.0', 8], // RFC 1918
  ['100.64.0.0', 10], // CGNAT
  ['127.0.0.0', 8], // loopback
  ['169.254.0.0', 16], // link-local
  ['172.16.0.0', 12], // RFC 1918
  ['192.0.0.0', 24], // IETF protocol assignments
  ['192.0.2.0', 24], // TEST-NET-1
  ['192.168.0.0', 16], // RFC 1918
  ['198.18.0.0', 15], // benchmarking
  ['198.51.100.0', 24], // TEST-NET-2
  ['203.0.113.0', 24], // TEST-NET-3
  ['224.0.0.0', 4], // multicast
  ['240.0.0.0', 4], // reservado + broadcast
];

const NON_PUBLIC_TLDS = ['localhost', 'local', 'internal', 'lan', 'home', 'corp', 'test', 'example', 'invalid', 'onion'];

function ipv4ToInt(ip: string): number {
  return ip.split('.').reduce((acc, octet) => (acc << 8) + Number(octet), 0) >>> 0;
}

function inCidr(ip: string, base: string, bits: number): boolean {
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return (ipv4ToInt(ip) & mask) === (ipv4ToInt(base) & mask);
}

/** Devuelve true si la IP no es enrutable públicamente. */
export function isPrivateOrReservedIp(ip: string): boolean {
  if (isIP(ip, 4)) {
    return PRIVATE_IPV4_RANGES.some(([base, bits]) => inCidr(ip, base, bits));
  }
  if (isIP(ip, 6)) {
    const v6 = ip.toLowerCase();
    if (v6 === '::' || v6 === '::1') return true;
    if (v6.startsWith('fe80:') || v6.startsWith('fc') || v6.startsWith('fd')) return true; // link-local / ULA
    if (v6.startsWith('ff')) return true; // multicast
    if (v6.startsWith('2001:db8:')) return true; // documentación
    const mapped = v6.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (mapped) return isPrivateOrReservedIp(mapped[1]);
    return false;
  }
  return true;
}

/** Devuelve true si el dominio no puede corresponder a un host público en Internet. */
export function isNonPublicHostname(host: string): boolean {
  const labels = host.split('.');
  if (labels.length < 2) return true; // "intranet", "localhost"
  const tld = labels[labels.length - 1];
  return NON_PUBLIC_TLDS.includes(tld);
}

/**
 * Normaliza el valor introducido por el usuario:
 * - recorta espacios, pasa a minúsculas
 * - elimina esquema (https://), ruta, puerto y punto final de FQDN
 */
export function normalizeAssetValue(raw: string): string {
  let value = raw.trim().toLowerCase();
  value = value.replace(/^[a-z][a-z0-9+.-]*:\/\//, ''); // esquema
  value = value.split(/[/?#]/)[0]; // ruta, query, fragmento
  if (value.startsWith('[')) {
    // IPv6 con corchetes, p. ej. [2001:db8::1]:443
    value = value.slice(1).split(']')[0];
  } else if (!isIP(value, 6)) {
    value = value.split(':')[0]; // puerto en dominio/IPv4
  }
  return value.replace(/\.$/, '');
}

export type AssetValidationResult =
  | { ok: true; type: AssetType; value: string }
  | { ok: false; reason: string };

export interface AssetValidationOptions {
  /** Modo laboratorio: acepta IPs privadas y hosts no públicos. */
  allowPrivate?: boolean;
}

/** Detecta el tipo y valida que el activo sea un dominio o IP pública. */
export function validateAssetValue(
  raw: string,
  expectedType?: AssetType,
  options: AssetValidationOptions = {},
): AssetValidationResult {
  const value = normalizeAssetValue(raw);
  if (!value) {
    return { ok: false, reason: 'El valor del activo no puede estar vacío' };
  }

  let type: AssetType;
  if (isIP(value)) {
    type = AssetType.IP;
    if (!options.allowPrivate && isPrivateOrReservedIp(value)) {
      return {
        ok: false,
        reason: `La IP ${value} es privada o reservada; solo se admiten activos públicos`,
      };
    }
  } else if (
    isFQDN(value, { require_tld: !options.allowPrivate, allow_underscores: false })
  ) {
    type = AssetType.DOMAIN;
    if (!options.allowPrivate && isNonPublicHostname(value)) {
      return {
        ok: false,
        reason: `El dominio ${value} no es público; solo se admiten activos accesibles desde Internet`,
      };
    }
  } else {
    return {
      ok: false,
      reason: `"${raw}" no es un dominio (FQDN) ni una dirección IP válida`,
    };
  }

  if (expectedType && expectedType !== type) {
    return {
      ok: false,
      reason: `El valor "${value}" corresponde a un activo de tipo ${type}, no ${expectedType}`,
    };
  }

  return { ok: true, type, value };
}
