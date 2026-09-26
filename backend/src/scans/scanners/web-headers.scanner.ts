import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { ScanType } from '@prisma/client';
import { analyzeHeaders } from '../analyzers/headers.analyzer';
import { ScanExecutionError } from '../scan.errors';
import { abortReason, FindingDraft, ScanContext, Scanner, ScanOutcome, requireTarget } from '../scanner.interface';
import { httpProbe, HttpProbeOutcome } from '../web/http-client';
import { webTargetsFor } from './web-targets';

/** RF-04: auditoría de cabeceras HTTP de seguridad. */
@Injectable()
export class WebHeadersScanner implements Scanner {
  readonly type = ScanType.WEB_HEADERS;

  constructor(private readonly config: ConfigService) {}

  async run(ctx: ScanContext): Promise<ScanOutcome> {
    const timeoutMs = this.config.get<number>('WEB_REQUEST_TIMEOUT_MS') ?? 10000;
    const targets = webTargetsFor(ctx.asset.value, ctx.openPorts, this.config);
    const probes: Array<{ target: (typeof targets)[number]; outcome: HttpProbeOutcome }> = [];

    for (const target of targets) {
      if (abortReason(ctx.signal)) throw new ScanExecutionError('Escaneo interrumpido');
      const outcome = await httpProbe(target.url, {
        allowPrivate: ctx.allowPrivate,
        signal: ctx.signal,
        timeoutMs,
        pinnedAddress: requireTarget(ctx).address,
        maxBodyBytes: 4096,
      });
      probes.push({ target, outcome });
    }

    const reachable = probes.filter((p) => p.outcome.ok);
    if (reachable.length === 0) {
      throw new ScanExecutionError(
        `Ningún servicio web respondió en ${targets.map((t) => t.url).join(', ')}`,
      );
    }

    const httpsAvailable = reachable.some((p) => p.outcome.ok && new URL(p.outcome.finalUrl).protocol === 'https:');
    const findings: FindingDraft[] = [];
    const audited: Record<string, unknown>[] = [];

    for (const { target, outcome } of probes) {
      if (!outcome.ok) {
        audited.push({ url: target.url, reachable: false, error: outcome.error, code: outcome.code ?? null });
        continue;
      }
      const drafts = analyzeHeaders({
        finalUrl: outcome.finalUrl,
        status: outcome.status,
        headers: outcome.headers,
        httpsAvailable,
      });
      findings.push(...drafts);
      audited.push({
        url: target.url,
        reachable: true,
        finalUrl: outcome.finalUrl,
        status: outcome.status,
        redirects: outcome.hops.length - 1,
        findings: drafts.length,
        headers: Object.fromEntries(
          Object.entries(outcome.headers).filter(([k]) => k !== 'set-cookie'),
        ),
        cookies: ([] as string[]).concat(outcome.headers['set-cookie'] ?? []).map((c) => c.split('=')[0]),
      });
    }

    return {
      parameters: { targets: targets.map((t) => t.url), timeoutMs, userAgentPinnedAddress: requireTarget(ctx).address },
      rawResult: { probes: audited },
      findings,
      summary: {
        targetsChecked: targets.length,
        targetsReachable: reachable.length,
        httpsAvailable,
        findingsCount: findings.length,
        urls: audited.map((a) => ({ url: a.url, reachable: a.reachable, finalUrl: a.finalUrl ?? null, status: a.status ?? null })),
      },
    };
  }
}
