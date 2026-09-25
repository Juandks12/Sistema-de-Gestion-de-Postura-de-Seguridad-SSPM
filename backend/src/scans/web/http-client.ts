import { AssetType } from '@prisma/client';
import { isIP } from 'node:net';
import { Agent, Dispatcher, request } from 'undici';
import { resolveScanTarget } from '../target-resolver';
import { ScanExecutionError } from '../scan.errors';

export interface HttpProbeOptions {
  /** Permite objetivos privados (modo laboratorio). */
  allowPrivate: boolean;
  signal: AbortSignal;
  timeoutMs?: number;
  maxRedirects?: number;
  maxBodyBytes?: number;
  method?: 'GET' | 'HEAD';
  headers?: Record<string, string>;
  /** IP ya resuelta para el host inicial (evita una segunda resolución DNS). */
  pinnedAddress?: string;
}

export interface HttpHop {
  url: string;
  status: number;
  location?: string;
}

export interface HttpProbeResult {
  ok: true;
  requestedUrl: string;
  finalUrl: string;
  status: number;
  headers: Record<string, string | string[]>;
  body: Buffer;
  bodyTruncated: boolean;
  contentType: string;
  hops: HttpHop[];
  durationMs: number;
}

export interface HttpProbeFailure {
  ok: false;
  requestedUrl: string;
  error: string;
  code?: string;
  hops: HttpHop[];
  durationMs: number;
}

export type HttpProbeOutcome = HttpProbeResult | HttpProbeFailure;

export const USER_AGENT = 'SSPM-SaaS-Lite/0.2 (+security posture scanner)';

const DEFAULT_TIMEOUT_MS = 10000;
const DEFAULT_MAX_REDIRECTS = 5;
const DEFAULT_MAX_BODY = 256 * 1024;

function defaultPort(protocol: string): number {
  return protocol === 'https:' ? 443 : 80;
}

function bracket(address: string): string {
  return isIP(address) === 6 ? `[${address}]` : address;
}

function errorCode(err: unknown): string | undefined {
  const e = err as { code?: string; cause?: { code?: string } };
  return e?.code ?? e?.cause?.code;
}

async function readBody(body: Dispatcher.ResponseData['body'], max: number): Promise<{ buf: Buffer; truncated: boolean }> {
  const chunks: Buffer[] = [];
  let size = 0;
  let truncated = false;
  try {
    for await (const chunk of body) {
      const b = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array);
      if (size + b.length > max) {
        chunks.push(b.subarray(0, max - size));
        size = max;
        truncated = true;
        break;
      }
      chunks.push(b);
      size += b.length;
    }
  } finally {
    if (truncated) {
      body.destroy();
    }
  }
  return { buf: Buffer.concat(chunks), truncated };
}

/**
 * Cliente HTTP para auditoría (RF-04, RF-06) con protección contra SSRF:
 *
 * - Cada host (inicial y cada redirección) se resuelve y valida como público
 *   antes de conectar; la conexión se hace directamente a la IP validada y el
 *   nombre viaja en la cabecera Host / SNI, evitando una segunda resolución (TOCTOU).
 * - Sigue como máximo `maxRedirects` redirecciones y registra la cadena.
 * - No valida el certificado TLS (eso lo hace el módulo de certificados) para
 *   poder auditar cabeceras también en sitios con certificados inválidos.
 * - Limita el tamaño del cuerpo descargado.
 */
export async function httpProbe(url: string, options: HttpProbeOptions): Promise<HttpProbeOutcome> {
  const startedAt = Date.now();
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxRedirects = options.maxRedirects ?? DEFAULT_MAX_REDIRECTS;
  const maxBody = options.maxBodyBytes ?? DEFAULT_MAX_BODY;
  const hops: HttpHop[] = [];
  let current = url;
  let pinned = options.pinnedAddress;

  for (let redirects = 0; ; redirects += 1) {
    let parsed: URL;
    try {
      parsed = new URL(current);
    } catch {
      return { ok: false, requestedUrl: url, error: `URL inválida: ${current}`, hops, durationMs: Date.now() - startedAt };
    }
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return { ok: false, requestedUrl: url, error: `Esquema no soportado: ${parsed.protocol}`, hops, durationMs: Date.now() - startedAt };
    }

    const hostname = parsed.hostname.replace(/^\[|\]$/g, '');
    const port = parsed.port ? Number(parsed.port) : defaultPort(parsed.protocol);
    const hostIsIp = isIP(hostname) !== 0;

    let address = pinned;
    pinned = undefined;
    if (!address) {
      try {
        const resolved = await resolveScanTarget(
          hostname,
          hostIsIp ? AssetType.IP : AssetType.DOMAIN,
          options.allowPrivate,
        );
        address = resolved.address;
      } catch (err) {
        const message = err instanceof ScanExecutionError ? err.message : `No se pudo resolver ${hostname}`;
        return { ok: false, requestedUrl: url, error: message, hops, durationMs: Date.now() - startedAt };
      }
    }

    const agent = new Agent({
      connect: {
        rejectUnauthorized: false,
        servername: hostIsIp ? undefined : hostname,
        timeout: timeoutMs,
      },
      connections: 1,
      pipelining: 0,
    });

    try {
      const hostHeader = port === defaultPort(parsed.protocol) ? bracket(hostname) : `${bracket(hostname)}:${port}`;
      const res = await request(`${parsed.protocol}//${bracket(address)}:${port}${parsed.pathname}${parsed.search}`, {
        dispatcher: agent,
        method: options.method ?? 'GET',
        headers: {
          host: hostHeader,
          'user-agent': USER_AGENT,
          accept: '*/*',
          'accept-encoding': 'identity',
          ...options.headers,
        },
        signal: options.signal,
        headersTimeout: timeoutMs,
        bodyTimeout: timeoutMs,
      });

      const headers: Record<string, string | string[]> = {};
      for (const [k, v] of Object.entries(res.headers)) {
        if (v !== undefined) headers[k.toLowerCase()] = v;
      }
      const location = typeof headers.location === 'string' ? headers.location : undefined;
      hops.push({ url: current, status: res.statusCode, location });

      if (res.statusCode >= 300 && res.statusCode < 400 && location && redirects < maxRedirects) {
        await res.body.dump().catch(() => undefined);
        current = new URL(location, current).toString();
        continue;
      }

      const { buf, truncated } = await readBody(res.body, maxBody);
      const contentType = typeof headers['content-type'] === 'string' ? headers['content-type'] : '';
      return {
        ok: true,
        requestedUrl: url,
        finalUrl: current,
        status: res.statusCode,
        headers,
        body: buf,
        bodyTruncated: truncated,
        contentType,
        hops,
        durationMs: Date.now() - startedAt,
      };
    } catch (err) {
      const code = errorCode(err);
      const message = (err as Error).message ?? 'Error de red';
      return { ok: false, requestedUrl: url, error: message, code, hops, durationMs: Date.now() - startedAt };
    } finally {
      await agent.close().catch(() => undefined);
    }
  }
}
