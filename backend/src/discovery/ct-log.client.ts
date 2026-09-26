import { Injectable, Logger } from '@nestjs/common';
import { CtName } from './hostnames';

/** Fuente de Certificate Transparency. Se inyecta con `CT_SOURCE` para sustituirla en las pruebas. */
export interface CtSource {
  names(domain: string, signal: AbortSignal): Promise<{ source: string; names: CtName[] }>;
}

export const CT_SOURCE = Symbol('CT_SOURCE');

export class CtSourceError extends Error {}

const REQUEST_TIMEOUT_MS = 60_000;
/** Límite de tamaño de una respuesta (los dominios grandes tienen miles de certificados). */
const MAX_RESPONSE_BYTES = 30 * 1024 * 1024;
const CERTSPOTTER_MAX_PAGES = 5;

async function readJson<T>(res: Response): Promise<T> {
  if (!res.body) throw new CtSourceError('Respuesta vacía');
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > MAX_RESPONSE_BYTES) {
      await reader.cancel();
      throw new CtSourceError('La respuesta supera el tamaño máximo permitido');
    }
    chunks.push(value);
  }
  return JSON.parse(Buffer.concat(chunks).toString('utf8')) as T;
}

/**
 * Consulta los registros públicos de Certificate Transparency: todo
 * certificado TLS emitido por una CA pública queda registrado con sus
 * nombres, así que revelan los subdominios en uso sin tocar la
 * infraestructura del cliente. Usa crt.sh y, si falla (es frecuente que esté
 * saturado), la API de Cert Spotter.
 */
@Injectable()
export class CtLogClient implements CtSource {
  private readonly logger = new Logger(CtLogClient.name);

  private async fetch(url: string, signal: AbortSignal): Promise<Response> {
    const res = await fetch(url, {
      headers: { accept: 'application/json', 'user-agent': 'SSPM-SaaS-Lite (subdomain discovery)' },
      signal: AbortSignal.any([signal, AbortSignal.timeout(REQUEST_TIMEOUT_MS)]),
    });
    if (!res.ok) throw new CtSourceError(`HTTP ${res.status}`);
    return res;
  }

  private async crtSh(domain: string, signal: AbortSignal): Promise<CtName[]> {
    const url = `https://crt.sh/?q=${encodeURIComponent(`%.${domain}`)}&output=json&exclude=expired`;
    const rows = await readJson<Array<{ name_value?: string; common_name?: string; not_before?: string }>>(await this.fetch(url, signal));
    return rows.flatMap((r) =>
      [r.name_value, r.common_name].filter((n): n is string => !!n).map((name) => ({ name, notBefore: r.not_before ?? null })),
    );
  }

  private async certSpotter(domain: string, signal: AbortSignal): Promise<CtName[]> {
    const names: CtName[] = [];
    let after: string | null = null;
    for (let page = 0; page < CERTSPOTTER_MAX_PAGES; page += 1) {
      const url: string =
        `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(domain)}` +
        `&include_subdomains=true&expand=dns_names${after ? `&after=${encodeURIComponent(after)}` : ''}`;
      type Issuance = { id?: string; dns_names?: string[]; not_before?: string };
      const rows: Issuance[] = await readJson<Issuance[]>(await this.fetch(url, signal));
      for (const r of rows) {
        for (const name of r.dns_names ?? []) names.push({ name, notBefore: r.not_before ?? null });
      }
      if (rows.length === 0 || !rows[rows.length - 1].id) break;
      after = rows[rows.length - 1].id ?? null;
    }
    return names;
  }

  async names(domain: string, signal: AbortSignal): Promise<{ source: string; names: CtName[] }> {
    const errors: string[] = [];
    for (const [source, query] of [
      ['crt.sh', () => this.crtSh(domain, signal)],
      ['certspotter', () => this.certSpotter(domain, signal)],
    ] as const) {
      try {
        return { source, names: await query() };
      } catch (err) {
        if (signal.aborted) throw err;
        const message = `${source}: ${(err as Error).message}`;
        this.logger.warn(`Certificate Transparency (${domain}) - ${message}`);
        errors.push(message);
      }
    }
    throw new CtSourceError(`No se pudo consultar Certificate Transparency (${errors.join('; ')})`);
  }
}
