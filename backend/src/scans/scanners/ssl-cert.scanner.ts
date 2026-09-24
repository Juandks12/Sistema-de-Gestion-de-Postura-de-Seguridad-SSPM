import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { ScanType } from '@prisma/client';
import { analyzeTls } from '../analyzers/tls.analyzer';
import { ScanExecutionError } from '../scan.errors';
import { abortReason, FindingDraft, ScanContext, Scanner, ScanOutcome } from '../scanner.interface';
import { tcpPortOpen, tlsProbe } from '../web/tls-probe';
import { webTargetsFor } from './web-targets';

/** RF-05: validación de certificados y configuración TLS. */
@Injectable()
export class SslCertScanner implements Scanner {
  readonly type = ScanType.SSL_CERT;

  constructor(private readonly config: ConfigService) {}

  async run(ctx: ScanContext): Promise<ScanOutcome> {
    const timeoutMs = this.config.get<number>('WEB_REQUEST_TIMEOUT_MS') ?? 10000;
    const targets = webTargetsFor(ctx.asset.value, ctx.openPorts, this.config);
    const tlsPorts = targets.filter((t) => t.scheme === 'https').map((t) => t.port);
    const httpPorts = targets.filter((t) => t.scheme === 'http').map((t) => t.port);
    const findings: FindingDraft[] = [];
    const results: Record<string, unknown>[] = [];
    let reachable = 0;

    for (const port of tlsPorts) {
      if (abortReason(ctx.signal)) throw new ScanExecutionError('Escaneo interrumpido');
      const outcome = await tlsProbe({
        address: ctx.target.address,
        port,
        hostname: ctx.asset.value,
        timeoutMs,
        signal: ctx.signal,
      });

      if (!outcome.ok) {
        results.push({ port, reachable: false, error: outcome.error, code: outcome.code ?? null });
        // Sin TLS en el puerto por defecto pero con HTTP en claro: el sitio no ofrece HTTPS.
        if (port === 443 && outcome.connectionRefused) {
          const plainOpen =
            httpPorts.length > 0 && (await tcpPortOpen(ctx.target.address, httpPorts[0], timeoutMs));
          if (plainOpen) {
            findings.push({
              ruleId: 'TLS-NOT-AVAILABLE',
              location: `tls://${ctx.asset.value}:443`,
              evidence: { httpPort: httpPorts[0], tlsPort: 443, error: outcome.error },
            });
          }
        }
        continue;
      }

      reachable += 1;
      const drafts = analyzeTls(outcome.info);
      findings.push(...drafts);
      const cert = outcome.info.certificate;
      results.push({
        port,
        reachable: true,
        protocol: outcome.info.protocol,
        cipher: outcome.info.cipher,
        authorized: outcome.info.authorized,
        authorizationError: outcome.info.authorizationError,
        hostnameError: outcome.info.hostnameError,
        legacyProtocolSupported: outcome.info.legacyProtocolSupported,
        chainLength: outcome.info.chainLength,
        certificate: cert,
        findings: drafts.length,
      });
    }

    if (reachable === 0 && findings.length === 0) {
      throw new ScanExecutionError(
        `No se pudo establecer TLS en ${tlsPorts.map((p) => `${ctx.asset.value}:${p}`).join(', ')}`,
      );
    }

    const primary = results.find((r) => r.reachable) as { certificate?: { validTo: string; issuer: string; subject: string } } | undefined;
    return {
      parameters: { tlsPorts, httpPorts, timeoutMs, hostname: ctx.asset.value },
      rawResult: { probes: results },
      findings,
      summary: {
        portsChecked: tlsPorts.length,
        portsWithTls: reachable,
        findingsCount: findings.length,
        certificate: primary?.certificate
          ? { subject: primary.certificate.subject, issuer: primary.certificate.issuer, validTo: primary.certificate.validTo }
          : null,
        protocols: results.filter((r) => r.reachable).map((r) => ({ port: r.port, protocol: r.protocol, legacy: r.legacyProtocolSupported })),
      },
    };
  }
}
