import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { ScanType } from '@prisma/client';
import { analyzePorts } from '../analyzers/ports.analyzer';
import { buildNmapArgs } from '../nmap/nmap-args';
import { parseNmapXml } from '../nmap/nmap-xml.parser';
import { NmapRunner } from '../nmap/nmap.runner';
import { NmapProfile } from '../nmap/nmap.types';
import { ScanExecutionError } from '../scan.errors';
import { abortReason, ScanContext, Scanner, ScanOutcome } from '../scanner.interface';

/** RF-02 / RF-03: puertos abiertos y versiones de servicios con Nmap. */
@Injectable()
export class PortScanScanner implements Scanner {
  readonly type = ScanType.PORT_SCAN;

  constructor(
    private readonly runner: NmapRunner,
    private readonly config: ConfigService,
  ) {}

  private profile(timeoutMs: number): NmapProfile {
    const ports = this.config.get<string>('SCAN_PORTS')?.trim();
    return {
      topPorts: this.config.get<number>('SCAN_TOP_PORTS') ?? 1000,
      ports: ports ? ports : undefined,
      timing: this.config.get<number>('SCAN_TIMING_TEMPLATE') ?? 4,
      // Nmap termina un poco antes que el timeout duro para poder devolver XML parcial.
      hostTimeoutSeconds: Math.max(15, Math.floor(timeoutMs / 1000) - 15),
    };
  }

  async run(ctx: ScanContext): Promise<ScanOutcome> {
    const profile = this.profile(ctx.timeoutMs);
    const args = buildNmapArgs(ctx.target.address, profile);
    const output = await this.runner.run(args, { timeoutMs: ctx.timeoutMs, signal: ctx.signal });

    if (output.cancelled || abortReason(ctx.signal)) {
      throw new ScanExecutionError('Escaneo interrumpido');
    }
    if (output.timedOut) {
      throw new ScanExecutionError(`El escaneo superó el tiempo máximo permitido (${Math.round(ctx.timeoutMs / 1000)} s)`);
    }
    if (output.exitCode !== 0) {
      const detail = output.stderr.trim().split('\n').slice(-3).join(' ').slice(0, 300);
      throw new ScanExecutionError(`Nmap terminó con código ${output.exitCode}${detail ? `: ${detail}` : ''}`);
    }

    const result = parseNmapXml(output.stdout);
    const host = result.hosts[0];
    const ports = host?.ports ?? [];
    const openPorts = ports.filter((p) => p.state === 'open');

    return {
      parameters: { tool: 'nmap', args, profile: { ...profile } },
      rawResult: result,
      ports,
      findings: analyzePorts(ports),
      summary: {
        hostStatus: host?.status ?? 'unknown',
        openPortsCount: openPorts.length,
        scannedPortsCount: ports.length + (host?.extraPorts ?? []).reduce((acc, e) => acc + e.count, 0),
        openPorts: openPorts.map((p) => ({
          port: p.port,
          protocol: p.protocol,
          service: p.service?.name ?? null,
          product: p.service?.product ?? null,
          version: p.service?.version ?? null,
          tunnel: p.service?.tunnel ?? null,
        })),
        durationSeconds: Math.round(output.durationMs / 100) / 10,
        nmapVersion: result.version ?? null,
      },
    };
  }
}
