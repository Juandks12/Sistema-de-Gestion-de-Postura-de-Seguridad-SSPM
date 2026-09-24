import { isFQDN } from 'class-validator';
import { isIP } from 'node:net';
import { AssetType } from '../generated/prisma/client';

export interface NormalizedTarget {
  type: AssetType;
  value: string;
}

export class InvalidTargetError extends Error {}

/**
 * Normaliza y clasifica el objetivo de un activo (RF-01).
 *
 * - Acepta un FQDN ("www.acme.com") o una IP v4/v6 ("203.0.113.10").
 * - Rechaza URLs completas, rutas, puertos y "localhost".
 * - Opcionalmente rechaza IPs privadas/reservadas: el alcance del proyecto
 *   (secciones 1.5 y 1.6) se limita a activos expuestos públicamente.
 */
export function normalizeTarget(
  raw: string,
  options: { allowPrivate?: boolean } = {},
): NormalizedTarget {
  let value = raw.trim().toLowerCase();

  if (value.length === 0) {
    throw new InvalidTargetError('El valor del activo no puede estar vacío');
  }
  if (/^[a-z][a-z0-9+.-]*:\/\//.test(value) || value.includes('/')) {
    throw new InvalidTargetError(
      'Indica solo el dominio o la IP, sin esquema (http://) ni rutas (/path)',
    );
  }

  // IPv6 entre corchetes: "[2001:db8::1]"
  if (value.startsWith('[') && value.endsWith(']')) {
    value = value.slice(1, -1);
  }

  const ipVersion = isIP(value);
  if (ipVersion !== 0) {
    if (!options.allowPrivate && !isPublicIp(value, ipVersion)) {
      throw new InvalidTargetError(
        'Solo se permiten direcciones IP públicas; las redes privadas quedan fuera del alcance',
      );
    }
    return { type: AssetType.IP, value };
  }

  // Dominio: se elimina el punto final de un FQDN absoluto ("acme.com.").
  value = value.replace(/\.$/, '');
  if (value.includes(':')) {
    throw new InvalidTargetError('No incluyas el puerto en el dominio');
  }
  if (value === 'localhost' || value.endsWith('.localhost') || value.endsWith('.local')) {
    throw new InvalidTargetError('Los nombres locales no son activos externos válidos');
  }
  if (!isFQDN(value, { require_tld: true, allow_underscores: false, allow_trailing_dot: false })) {
    throw new InvalidTargetError(
      'El valor debe ser un dominio válido (ej. www.acme.com) o una IP pública',
    );
  }
  return { type: AssetType.DOMAIN, value };
}

/** Determina si una IP es enrutable públicamente (no privada, loopback, link-local, multicast...). */
export function isPublicIp(ip: string, version: 4 | 6 | number = isIP(ip)): boolean {
  if (version === 4) {
    return isPublicIpv4(ip);
  }
  if (version === 6) {
    return isPublicIpv6(ip);
  }
  return false;
}

function isPublicIpv4(ip: string): boolean {
  const [a, b] = ip.split('.').map(Number);
  if (a === 0 || a === 10 || a === 127) return false; // "this" network, privada, loopback
  if (a === 100 && b >= 64 && b <= 127) return false; // CGNAT 100.64.0.0/10
  if (a === 169 && b === 254) return false; // link-local
  if (a === 172 && b >= 16 && b <= 31) return false; // privada 172.16.0.0/12
  if (a === 192 && b === 168) return false; // privada
  if (a === 192 && b === 0) return false; // 192.0.0.0/24 y 192.0.2.0/24 (documentación)
  if (a === 198 && (b === 18 || b === 19)) return false; // benchmarking
  if (a === 198 && b === 51) return false; // 198.51.100.0/24 documentación
  if (a === 203 && b === 0) return false; // 203.0.113.0/24 documentación
  if (a >= 224) return false; // multicast y reservado
  return true;
}

function isPublicIpv6(ip: string): boolean {
  const lower = ip.toLowerCase();
  if (lower === '::' || lower === '::1') return false;
  // IPv4 mapeada (::ffff:a.b.c.d) -> evaluar la IPv4 embebida.
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/.exec(lower);
  if (mapped) return isPublicIpv4(mapped[1]);
  if (/^f[cd]/.test(lower)) return false; // ULA fc00::/7
  if (/^fe[89ab]/.test(lower)) return false; // link-local fe80::/10
  if (lower.startsWith('ff')) return false; // multicast
  if (lower.startsWith('2001:db8:')) return false; // documentación
  return true;
}
