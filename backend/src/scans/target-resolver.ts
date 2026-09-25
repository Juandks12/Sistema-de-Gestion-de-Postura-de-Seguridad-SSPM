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

/**
 * Resuelve el activo a una IP concreta justo antes del escaneo.
 *
 * Protección contra abuso del escáner (sección 11.3): un dominio registrado como
 * público podría apuntar después (o mediante DNS rebinding) a una red interna.
 * Si alguna dirección resuelta es privada/reservada se bloquea el escaneo, y a
 * Nmap se le entrega la IP ya validada para evitar una segunda resolución (TOCTOU).
 */
export async function resolveScanTarget(
  value: string,
  type: AssetType,
  allowPrivate: boolean,
  lookup: LookupFn = dnsLookup as LookupFn,
): Promise<ResolvedTarget> {
  if (type === AssetType.IP) {
    const family = isIP(value);
    if (family === 0) {
      throw new ScanExecutionError(`La dirección IP ${value} no es válida`);
    }
    if (!allowPrivate && isPrivateOrReservedIp(value)) {
      throw new ScanExecutionError(`La IP ${value} es privada o reservada; escaneo bloqueado`);
    }
    return { address: value, family: family as 4 | 6, resolvedAddresses: [value] };
  }

  let addresses: LookupAddress[];
  try {
    addresses = await lookup(value, { all: true, verbatim: true });
  } catch {
    throw new ScanExecutionError(`No se pudo resolver el dominio ${value}`);
  }
  if (addresses.length === 0) {
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
  return {
    address: chosen.address,
    family: chosen.family as 4 | 6,
    resolvedAddresses: addresses.map((a) => a.address),
  };
}
