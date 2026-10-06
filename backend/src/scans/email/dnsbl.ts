import { isIP } from 'node:net';
import { DnsClient } from '../../common/dns/dns-client';

export interface DnsblListing {
  ip: string;
  exchange: string;
  provider: string;
  returnCodes: string[];
  txt?: string;
}

export interface DnsblResult {
  checked: boolean;
  totalIpsChecked: number;
  listings: DnsblListing[];
  clean: boolean;
}

export const DEFAULT_DNSBL_PROVIDERS = ['zen.spamhaus.org', 'bl.spamcop.net'];

/**
 * Invierte una dirección IP para consulta DNSBL (RFC 5782).
 * IPv4: 198.51.100.25 -> 25.100.51.198
 * IPv6: 2001:db8::1 -> 1.0.0.0.0.0...8.b.d.0.1.0.0.2
 */
export function reverseIp(ip: string): string | null {
  const version = isIP(ip);
  if (version === 4) {
    const parts = ip.split('.');
    if (parts.length !== 4) return null;
    return parts.reverse().join('.');
  }

  if (version === 6) {
    // Expande IPv6 a 32 caracteres hexadecimales
    let full = ip.toLowerCase();
    if (full.includes('::')) {
      const sides = full.split('::');
      const left = sides[0] ? sides[0].split(':') : [];
      const right = sides[1] ? sides[1].split(':') : [];
      const missing = 8 - (left.length + right.length);
      const zeros = Array(missing).fill('0');
      full = [...left, ...zeros, ...right].join(':');
    }
    const hextets = full.split(':');
    if (hextets.length !== 8) return null;
    const nibbles = hextets
      .map((h) => h.padStart(4, '0'))
      .join('')
      .split('');
    return nibbles.reverse().join('.');
  }

  return null;
}

/**
 * Verifica si una dirección IP está listada en los proveedores DNSBL configurados.
 */
export async function checkIpDnsbl(
  ip: string,
  exchange: string,
  dns: DnsClient,
  providers: string[] = DEFAULT_DNSBL_PROVIDERS,
): Promise<DnsblListing[]> {
  const reversed = reverseIp(ip);
  if (!reversed) return [];

  const listings: DnsblListing[] = [];

  for (const provider of providers) {
    const queryHost = `${reversed}.${provider}`;
    let returnCodes: string[];

    try {
      returnCodes = await dns.addresses(queryHost);
    } catch {
      continue;
    }

    if (returnCodes.length === 0) continue;

    // Spamhaus: 127.255.255.x son códigos de error o límite de cuota en resolutores abiertos, no listados reales.
    const validCodes = returnCodes.filter((code) => !code.startsWith('127.255.255.'));
    if (validCodes.length === 0) continue;

    let txtReason: string | undefined;
    try {
      const txt = await dns.txt(queryHost);
      if (txt.length > 0) {
        txtReason = txt.join('; ');
      }
    } catch {
      // Si la consulta TXT falla, conservamos la detección por dirección A
    }

    listings.push({
      ip,
      exchange,
      provider,
      returnCodes: validCodes,
      txt: txtReason,
    });
  }

  return listings;
}

/**
 * Resuelve las IPs de todos los servidores de correo (MX) de un dominio y
 * audita su reputación en las listas negras DNSBL (zen.spamhaus.org y bl.spamcop.net).
 */
export async function auditMailExchangersDnsbl(
  mxExchanges: string[],
  dns: DnsClient,
  providers: string[] = DEFAULT_DNSBL_PROVIDERS,
): Promise<DnsblResult> {
  if (mxExchanges.length === 0) {
    return {
      checked: false,
      totalIpsChecked: 0,
      listings: [],
      clean: true,
    };
  }

  // Resuelve IPs de los hostnames MX
  const ipToExchange = new Map<string, string>();

  await Promise.all(
    mxExchanges.map(async (exchange) => {
      try {
        const ips = await dns.addresses(exchange);
        for (const ip of ips) {
          if (!ipToExchange.has(ip)) {
            ipToExchange.set(ip, exchange);
          }
        }
      } catch {
        // Si no resuelve este MX, continúa con los demás
      }
    }),
  );

  const uniqueIps = Array.from(ipToExchange.keys());
  if (uniqueIps.length === 0) {
    return {
      checked: true,
      totalIpsChecked: 0,
      listings: [],
      clean: true,
    };
  }

  const allListings: DnsblListing[] = [];

  await Promise.all(
    uniqueIps.map(async (ip) => {
      const exchange = ipToExchange.get(ip) ?? '';
      const listings = await checkIpDnsbl(ip, exchange, dns, providers);
      allListings.push(...listings);
    }),
  );

  return {
    checked: true,
    totalIpsChecked: uniqueIps.length,
    listings: allListings,
    clean: allListings.length === 0,
  };
}
