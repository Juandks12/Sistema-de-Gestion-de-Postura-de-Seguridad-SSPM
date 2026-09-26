import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { ScanType } from '@prisma/client';
import { randomBytes } from 'node:crypto';
import { ScanExecutionError } from '../scan.errors';
import { abortReason, FindingDraft, ScanContext, Scanner, ScanOutcome, requireTarget } from '../scanner.interface';
import { httpProbe, HttpProbeOptions, HttpProbeResult } from '../web/http-client';
import { PathResponse, SENSITIVE_PATHS, SensitivePathRule } from '../web/sensitive-paths.catalog';
import { buildUrl, webTargetsFor } from './web-targets';

const MAX_BODY = 64 * 1024;

interface PathCheck {
  rule: SensitivePathRule;
  url: string;
  status: number | null;
  matched: boolean;
  error?: string;
}

function toPathResponse(res: HttpProbeResult): PathResponse {
  return {
    status: res.status,
    contentType: res.contentType,
    body: res.body,
    text: res.body.toString('utf8'),
  };
}

/**
 * Ejecuta tareas con un límite de concurrencia preservando el orden de los resultados.
 */
async function mapWithConcurrency<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    for (;;) {
      const index = next;
      next += 1;
      if (index >= items.length) return;
      results[index] = await fn(items[index]);
    }
  });
  await Promise.all(workers);
  return results;
}

/** RF-06: detección de archivos y rutas sensibles expuestas. */
@Injectable()
export class SensitivePathsScanner implements Scanner {
  readonly type = ScanType.SENSITIVE_PATHS;

  constructor(private readonly config: ConfigService) {}

  async run(ctx: ScanContext): Promise<ScanOutcome> {
    const timeoutMs = this.config.get<number>('WEB_REQUEST_TIMEOUT_MS') ?? 10000;
    const concurrency = this.config.get<number>('WEB_PATHS_CONCURRENCY') ?? 4;
    const targets = webTargetsFor(ctx.asset.value, ctx.openPorts, this.config);
    const probeOptions: Omit<HttpProbeOptions, 'signal'> = {
      allowPrivate: ctx.allowPrivate,
      timeoutMs,
      pinnedAddress: requireTarget(ctx).address,
      maxBodyBytes: MAX_BODY,
      maxRedirects: 2,
    };

    // Se audita el primer origen que responda (preferencia HTTPS).
    let base: { scheme: 'http' | 'https'; port: number } | undefined;
    for (const target of targets) {
      const res = await httpProbe(target.url, { ...probeOptions, signal: ctx.signal });
      if (res.ok) {
        base = { scheme: target.scheme, port: target.port };
        break;
      }
    }
    if (!base) {
      throw new ScanExecutionError(`Ningún servicio web respondió en ${targets.map((t) => t.url).join(', ')}`);
    }
    const baseUrl = buildUrl(base.scheme, ctx.asset.value, base.port, '');

    // Línea base para detectar "soft 404": sitios que responden 200 a cualquier ruta.
    const canary = `/${randomBytes(8).toString('hex')}-sspm-probe`;
    const canaryRes = await httpProbe(`${baseUrl}${canary}`, { ...probeOptions, signal: ctx.signal });
    const softNotFound = canaryRes.ok && canaryRes.status >= 200 && canaryRes.status < 300;

    const checks = await mapWithConcurrency(SENSITIVE_PATHS, concurrency, async (rule): Promise<PathCheck> => {
      if (abortReason(ctx.signal)) {
        return { rule, url: `${baseUrl}${rule.path}`, status: null, matched: false, error: 'interrumpido' };
      }
      const url = `${baseUrl}${rule.path}`;
      const res = await httpProbe(url, { ...probeOptions, signal: ctx.signal });
      if (!res.ok) {
        return { rule, url, status: null, matched: false, error: res.error };
      }
      // Solo se aceptan respuestas satisfactorias (o 401 para reglas que lo contemplan)
      // y siempre con firma de contenido, lo que neutraliza los soft 404.
      const candidate = (res.status >= 200 && res.status < 300) || res.status === 401;
      const matched = candidate && rule.signature(toPathResponse(res));
      return { rule, url, status: res.status, matched };
    });

    if (abortReason(ctx.signal)) throw new ScanExecutionError('Escaneo interrumpido');

    const findings: FindingDraft[] = checks
      .filter((c) => c.matched)
      .map((c) => ({
        ruleId: c.rule.ruleId,
        location: c.url,
        title: `${c.rule.label} accesible públicamente (${c.rule.path})`,
        // Nunca se guarda el contenido: puede contener secretos.
        evidence: { path: c.rule.path, status: c.status, signatureMatched: true },
      }));

    return {
      parameters: { baseUrl, pathsChecked: SENSITIVE_PATHS.length, concurrency, timeoutMs },
      rawResult: {
        baseUrl,
        softNotFound,
        canaryStatus: canaryRes.ok ? canaryRes.status : null,
        checks: checks.map((c) => ({ path: c.rule.path, status: c.status, matched: c.matched, error: c.error ?? null })),
      },
      findings,
      summary: {
        baseUrl,
        softNotFound,
        pathsChecked: checks.length,
        pathsUnreachable: checks.filter((c) => c.error).length,
        exposed: findings.map((f) => f.location),
        findingsCount: findings.length,
      },
    };
  }
}
