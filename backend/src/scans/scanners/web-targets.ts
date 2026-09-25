import { ConfigService } from '@nestjs/config';
import { isIP } from 'node:net';
import { OpenPortHint } from '../scanner.interface';

export interface WebTarget {
  scheme: 'http' | 'https';
  port: number;
  url: string;
}

const HTTPS_SERVICES = new Set(['https', 'https-alt', 'ssl/http', 'ssl/http-alt']);
const HTTP_SERVICES = new Set(['http', 'http-alt', 'http-proxy', 'www', 'http-mgmt', 'webcache']);

function parsePorts(value: string | undefined, fallback: number[]): number[] {
  if (!value) return fallback;
  return value
    .split(',')
    .map((p) => Number(p.trim()))
    .filter((p) => Number.isInteger(p) && p > 0 && p < 65536);
}

export function hostForUrl(hostname: string): string {
  return isIP(hostname) === 6 ? `[${hostname}]` : hostname;
}

export function buildUrl(scheme: 'http' | 'https', hostname: string, port: number, path = '/'): string {
  const isDefault = (scheme === 'https' && port === 443) || (scheme === 'http' && port === 80);
  return `${scheme}://${hostForUrl(hostname)}${isDefault ? '' : `:${port}`}${path}`;
}

/**
 * Determina qué URLs auditar a partir de la configuración y de los puertos
 * abiertos conocidos por el último escaneo de puertos.
 */
export function webTargetsFor(hostname: string, openPorts: OpenPortHint[], config: ConfigService): WebTarget[] {
  const https = new Set(parsePorts(config.get<string>('WEB_HTTPS_PORTS'), [443]));
  const http = new Set(parsePorts(config.get<string>('WEB_HTTP_PORTS'), [80]));

  for (const p of openPorts) {
    if (p.protocol !== 'tcp') continue;
    const name = p.serviceName?.toLowerCase() ?? '';
    if (p.tunnel === 'ssl' || HTTPS_SERVICES.has(name) || p.port === 8443) {
      https.add(p.port);
    } else if (HTTP_SERVICES.has(name) || p.port === 8080 || p.port === 8000) {
      http.add(p.port);
    }
  }

  const targets: WebTarget[] = [];
  for (const port of [...https].sort((a, b) => a - b)) {
    targets.push({ scheme: 'https', port, url: buildUrl('https', hostname, port) });
  }
  for (const port of [...http].sort((a, b) => a - b)) {
    if (https.has(port)) continue;
    targets.push({ scheme: 'http', port, url: buildUrl('http', hostname, port) });
  }
  return targets;
}
