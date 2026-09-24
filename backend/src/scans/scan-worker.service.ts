import { Injectable, Logger, OnApplicationBootstrap, OnApplicationShutdown } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Prisma, ScanStatus } from '@prisma/client';
import { validateAssetValue } from '../common/utils/network.util';
import { PrismaService } from '../prisma/prisma.service';
import { buildNmapArgs } from './nmap/nmap-args';
import { NmapParseError, parseNmapXml } from './nmap/nmap-xml.parser';
import { NmapRunner } from './nmap/nmap.runner';
import { NmapProfile, NmapScanResult } from './nmap/nmap.types';
import { ScanExecutionError } from './scan.errors';
import { resolveScanTarget } from './target-resolver';

/** Margen extra antes de considerar "huérfano" un escaneo RUNNING. */
const STALE_MARGIN_SECONDS = 120;

/**
 * Worker de escaneos. La cola vive en la propia tabla `scans` (status = PENDING):
 *
 * - Sobrevive a reinicios (los PENDING se retoman al arrancar).
 * - Permite varias instancias: cada una "reclama" trabajos con
 *   `FOR UPDATE SKIP LOCKED`, de modo que dos workers nunca toman el mismo escaneo.
 * - Respeta un límite global por instancia y un límite por organización.
 *
 * Si en el futuro se necesita más escala, este servicio puede moverse a un
 * proceso independiente (SCAN_WORKER_ENABLED=false en la API) sin cambiar la API.
 */
@Injectable()
export class ScanWorkerService implements OnApplicationBootstrap, OnApplicationShutdown {
  private readonly logger = new Logger(ScanWorkerService.name);
  private timer?: NodeJS.Timeout;
  private active = 0;
  private ticking = false;
  private tickRequested = false;
  private shuttingDown = false;
  private readonly inFlight = new Set<Promise<void>>();

  constructor(
    private readonly prisma: PrismaService,
    private readonly runner: NmapRunner,
    private readonly config: ConfigService,
  ) {}

  private get enabled(): boolean {
    return this.config.get<boolean>('SCAN_WORKER_ENABLED') !== false;
  }

  private get maxConcurrency(): number {
    return this.config.get<number>('SCAN_MAX_CONCURRENCY') ?? 2;
  }

  private get maxPerOrg(): number {
    return this.config.get<number>('SCAN_MAX_CONCURRENCY_PER_ORG') ?? 1;
  }

  private get timeoutSeconds(): number {
    return this.config.get<number>('SCAN_TIMEOUT_SECONDS') ?? 600;
  }

  private get allowPrivate(): boolean {
    return this.config.get<boolean>('ALLOW_PRIVATE_TARGETS') === true;
  }

  private get profile(): NmapProfile {
    const ports = this.config.get<string>('SCAN_PORTS')?.trim();
    return {
      topPorts: this.config.get<number>('SCAN_TOP_PORTS') ?? 1000,
      ports: ports ? ports : undefined,
      timing: this.config.get<number>('SCAN_TIMING_TEMPLATE') ?? 4,
      // Nmap termina un poco antes que el timeout duro del proceso para devolver XML parcial.
      hostTimeoutSeconds: Math.max(15, this.timeoutSeconds - 15),
    };
  }

  onApplicationBootstrap(): void {
    if (!this.enabled) {
      this.logger.log('Worker de escaneos deshabilitado (SCAN_WORKER_ENABLED=false)');
      return;
    }
    const interval = this.config.get<number>('SCAN_POLL_INTERVAL_MS') ?? 5000;
    this.timer = setInterval(() => this.kick(), interval);
    this.timer.unref();
    this.logger.log(
      `Worker de escaneos activo (concurrencia ${this.maxConcurrency}, ` +
        `${this.maxPerOrg} por organización, timeout ${this.timeoutSeconds}s)`,
    );
    this.kick();
  }

  async onApplicationShutdown(): Promise<void> {
    this.shuttingDown = true;
    if (this.timer) clearInterval(this.timer);
    const ids = this.runner.cancelAll();
    if (ids.length > 0) {
      this.logger.warn(`Apagado: ${ids.length} escaneo(s) en curso se devolverán a la cola`);
    }
    await Promise.allSettled([...this.inFlight]);
  }

  /** Solicita una revisión inmediata de la cola (p. ej. tras encolar un escaneo). */
  kick(): void {
    if (!this.enabled || this.shuttingDown) return;
    if (this.ticking) {
      this.tickRequested = true;
      return;
    }
    void this.tick();
  }

  private async tick(): Promise<void> {
    this.ticking = true;
    try {
      do {
        this.tickRequested = false;
        await this.failStaleScans();
        while (this.active < this.maxConcurrency && !this.shuttingDown) {
          const scanId = await this.claimNext();
          if (!scanId) break;
          this.active += 1;
          const job = this.execute(scanId).finally(() => {
            this.active -= 1;
            this.inFlight.delete(job);
            this.kick();
          });
          this.inFlight.add(job);
        }
      } while (this.tickRequested && !this.shuttingDown);
    } catch (err) {
      this.logger.error(`Error revisando la cola de escaneos: ${(err as Error).message}`);
    } finally {
      this.ticking = false;
    }
  }

  /** Toma atómicamente el siguiente escaneo PENDING respetando el límite por organización. */
  private async claimNext(): Promise<string | null> {
    const rows = await this.prisma.$queryRaw<Array<{ id: string }>>`
      UPDATE scans
         SET status = 'RUNNING', started_at = now(), updated_at = now()
       WHERE id = (
         SELECT s.id
           FROM scans s
          WHERE s.status = 'PENDING'
            AND (
              SELECT count(*) FROM scans r
               WHERE r.organization_id = s.organization_id AND r.status = 'RUNNING'
            ) < ${this.maxPerOrg}
          ORDER BY s.created_at
          LIMIT 1
          FOR UPDATE SKIP LOCKED
       )
      RETURNING id`;
    return rows[0]?.id ?? null;
  }

  /** Marca como fallidos los escaneos RUNNING abandonados (p. ej. caída del proceso). */
  private async failStaleScans(): Promise<void> {
    const limit = new Date(Date.now() - (this.timeoutSeconds + STALE_MARGIN_SECONDS) * 1000);
    const { count } = await this.prisma.scan.updateMany({
      where: { status: ScanStatus.RUNNING, startedAt: { lt: limit } },
      data: {
        status: ScanStatus.FAILED,
        finishedAt: new Date(),
        errorMessage: 'Escaneo interrumpido: el proceso que lo ejecutaba dejó de responder',
      },
    });
    if (count > 0) {
      this.logger.warn(`${count} escaneo(s) huérfano(s) marcados como FAILED`);
    }
  }

  private async execute(scanId: string): Promise<void> {
    const scan = await this.prisma.scan.findUnique({
      where: { id: scanId },
      include: { asset: true },
    });
    if (!scan) return;

    const { asset } = scan;
    this.logger.log(`Escaneo ${scanId}: iniciando sobre ${asset.value}`);

    try {
      if (!asset.isActive || !asset.authorizationConfirmed) {
        throw new ScanExecutionError('El activo está inactivo o no tiene autorización confirmada');
      }

      // Revalidación defensiva: el valor pudo cambiar o la política pudo endurecerse.
      const validation = validateAssetValue(asset.value, asset.type, {
        allowPrivate: this.allowPrivate,
      });
      if (!validation.ok) {
        throw new ScanExecutionError(validation.reason);
      }

      const target = await resolveScanTarget(validation.value, validation.type, this.allowPrivate);
      const profile = this.profile;
      const args = buildNmapArgs(target.address, profile);

      await this.prisma.scan.update({
        where: { id: scanId },
        data: {
          targetAddress: target.address,
          parameters: {
            tool: 'nmap',
            args,
            profile: { ...profile },
            timeoutSeconds: this.timeoutSeconds,
            resolvedAddresses: target.resolvedAddresses,
          } as Prisma.InputJsonValue,
        },
      });

      const output = await this.runner.run(scanId, args, this.timeoutSeconds * 1000);

      if (output.cancelled) {
        await this.handleInterrupted(scanId);
        return;
      }
      if (output.timedOut) {
        throw new ScanExecutionError(
          `El escaneo superó el tiempo máximo permitido (${this.timeoutSeconds} s)`,
        );
      }
      if (output.exitCode !== 0) {
        const detail = output.stderr.trim().split('\n').slice(-3).join(' ').slice(0, 300);
        throw new ScanExecutionError(
          `Nmap terminó con código ${output.exitCode}${detail ? `: ${detail}` : ''}`,
        );
      }

      const result = parseNmapXml(output.stdout);
      await this.persistResult(scanId, asset.id, scan.organizationId, asset.value, target.address, result, output.durationMs);
      this.logger.log(`Escaneo ${scanId}: completado en ${(output.durationMs / 1000).toFixed(1)} s`);
    } catch (err) {
      const message =
        err instanceof ScanExecutionError || err instanceof NmapParseError
          ? err.message
          : 'Error interno durante el escaneo';
      if (!(err instanceof ScanExecutionError)) {
        this.logger.error(`Escaneo ${scanId}: ${(err as Error).stack ?? String(err)}`);
      } else {
        this.logger.warn(`Escaneo ${scanId}: ${message}`);
      }
      await this.prisma.scan.updateMany({
        where: { id: scanId, status: ScanStatus.RUNNING },
        data: { status: ScanStatus.FAILED, finishedAt: new Date(), errorMessage: message },
      });
    }
  }

  /**
   * Proceso detenido: si fue por apagado del servidor se devuelve a la cola;
   * si fue una cancelación del usuario el estado CANCELLED ya está guardado.
   */
  private async handleInterrupted(scanId: string): Promise<void> {
    if (this.shuttingDown) {
      await this.prisma.scan.updateMany({
        where: { id: scanId, status: ScanStatus.RUNNING },
        data: { status: ScanStatus.PENDING, startedAt: null, targetAddress: null },
      });
      return;
    }
    await this.prisma.scan.updateMany({
      where: { id: scanId, status: ScanStatus.RUNNING },
      data: { status: ScanStatus.CANCELLED, finishedAt: new Date() },
    });
  }

  private async persistResult(
    scanId: string,
    assetId: string,
    organizationId: string,
    assetValue: string,
    targetAddress: string,
    result: NmapScanResult,
    durationMs: number,
  ): Promise<void> {
    const host = result.hosts[0];
    const ports = host?.ports ?? [];
    const openPorts = ports.filter((p) => p.state === 'open');
    const finishedAt = new Date();

    const summary = {
      target: assetValue,
      targetAddress,
      hostStatus: host?.status ?? 'unknown',
      openPortsCount: openPorts.length,
      scannedPortsCount:
        ports.length + (host?.extraPorts ?? []).reduce((acc, e) => acc + e.count, 0),
      openPorts: openPorts.map((p) => ({
        port: p.port,
        protocol: p.protocol,
        service: p.service?.name ?? null,
        product: p.service?.product ?? null,
        version: p.service?.version ?? null,
        tunnel: p.service?.tunnel ?? null,
      })),
      durationSeconds: Math.round(durationMs / 100) / 10,
      nmapVersion: result.version ?? null,
    };

    await this.prisma.$transaction(async (tx) => {
      // Si el usuario canceló mientras tanto, no se sobrescribe el estado.
      const updated = await tx.scan.updateMany({
        where: { id: scanId, status: ScanStatus.RUNNING },
        data: {
          status: ScanStatus.COMPLETED,
          finishedAt,
          rawResult: result as unknown as Prisma.InputJsonValue,
          summary: summary as Prisma.InputJsonValue,
          errorMessage: null,
        },
      });
      if (updated.count === 0) return;

      if (ports.length > 0) {
        await tx.scanPort.createMany({
          data: ports.map((p) => ({
            organizationId,
            scanId,
            assetId,
            port: p.port,
            protocol: p.protocol,
            state: p.state,
            reason: p.reason?.slice(0, 40),
            serviceName: p.service?.name?.slice(0, 100),
            product: p.service?.product?.slice(0, 200),
            version: p.service?.version?.slice(0, 100),
            extraInfo: p.service?.extraInfo?.slice(0, 255),
            tunnel: p.service?.tunnel?.slice(0, 20),
            cpe: p.service?.cpe ?? [],
            confidence: p.service?.confidence,
          })),
          skipDuplicates: true,
        });
      }

      await tx.asset.update({ where: { id: assetId }, data: { lastScannedAt: finishedAt } });
    });
  }
}
