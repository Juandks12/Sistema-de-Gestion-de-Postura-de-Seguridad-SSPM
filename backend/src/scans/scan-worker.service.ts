import { Inject, Injectable, Logger, OnApplicationBootstrap, OnApplicationShutdown } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Prisma, RiskScoreTrigger, ScanStatus, ScanType } from '@prisma/client';
import { AlertsService } from '../alerts/alerts.service';
import { validateAssetValue } from '../common/utils/network.util';
import { FindingsService, OpenedFinding, SyncFindingsResult } from '../findings/findings.service';
import { PrismaService } from '../prisma/prisma.service';
import { RiskScoresService } from '../risk/risk-scores.service';
import { NmapParseError } from './nmap/nmap-xml.parser';
import { ScanCancellationService } from './scan-cancellation.service';
import { ScanExecutionError } from './scan.errors';
import { abortReason, OpenPortHint, Scanner, SCANNERS, ScanOutcome } from './scanner.interface';
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
 * - Delega la ejecución en el `Scanner` registrado para cada `ScanType`.
 *
 * Si en el futuro se necesita más escala, este servicio puede moverse a un
 * proceso independiente (SCAN_WORKER_ENABLED=false en la API) sin cambiar la API.
 */
@Injectable()
export class ScanWorkerService implements OnApplicationBootstrap, OnApplicationShutdown {
  private readonly logger = new Logger(ScanWorkerService.name);
  private readonly scanners: Map<ScanType, Scanner>;
  private timer?: NodeJS.Timeout;
  private active = 0;
  private ticking = false;
  private tickRequested = false;
  private shuttingDown = false;
  private readonly inFlight = new Set<Promise<void>>();

  constructor(
    private readonly prisma: PrismaService,
    private readonly config: ConfigService,
    private readonly cancellation: ScanCancellationService,
    private readonly findings: FindingsService,
    private readonly riskScores: RiskScoresService,
    private readonly alerts: AlertsService,
    @Inject(SCANNERS) scanners: Scanner[],
  ) {
    this.scanners = new Map(scanners.map((s) => [s.type, s]));
  }

  /** Tipos de escaneo con un escáner registrado. */
  get supportedTypes(): ScanType[] {
    return [...this.scanners.keys()];
  }

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

  onApplicationBootstrap(): void {
    if (!this.enabled) {
      this.logger.log('Worker de escaneos deshabilitado (SCAN_WORKER_ENABLED=false)');
      return;
    }
    const interval = this.config.get<number>('SCAN_POLL_INTERVAL_MS') ?? 5000;
    this.timer = setInterval(() => this.kick(), interval);
    this.timer.unref();
    this.logger.log(
      `Worker de escaneos activo (tipos: ${this.supportedTypes.join(', ')}; concurrencia ${this.maxConcurrency}, ` +
        `${this.maxPerOrg} por organización, timeout ${this.timeoutSeconds}s)`,
    );
    this.kick();
  }

  async onApplicationShutdown(): Promise<void> {
    this.shuttingDown = true;
    if (this.timer) clearInterval(this.timer);
    const ids = this.cancellation.abortAll('shutdown');
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

  /** Puertos abiertos según el último escaneo de puertos completado del activo. */
  private async openPortsHint(assetId: string): Promise<OpenPortHint[]> {
    const last = await this.prisma.scan.findFirst({
      where: { assetId, type: ScanType.PORT_SCAN, status: ScanStatus.COMPLETED },
      orderBy: { finishedAt: 'desc' },
      select: {
        ports: {
          where: { state: 'open' },
          select: { port: true, protocol: true, serviceName: true, tunnel: true },
        },
      },
    });
    return last?.ports ?? [];
  }

  private async execute(scanId: string): Promise<void> {
    const scan = await this.prisma.scan.findUnique({ where: { id: scanId }, include: { asset: true } });
    if (!scan) return;

    const { asset } = scan;
    const timeoutMs = this.timeoutSeconds * 1000;
    const signal = this.cancellation.register(scanId, timeoutMs);
    this.logger.log(`Escaneo ${scanId} (${scan.type}): iniciando sobre ${asset.value}`);

    try {
      const scanner = this.scanners.get(scan.type);
      if (!scanner) {
        throw new ScanExecutionError(`El tipo de escaneo ${scan.type} no está disponible en esta instancia`);
      }
      if (!asset.isActive || !asset.authorizationConfirmed) {
        throw new ScanExecutionError('El activo está inactivo o no tiene autorización confirmada');
      }

      // Revalidación defensiva: el valor pudo cambiar o la política pudo endurecerse.
      const validation = validateAssetValue(asset.value, asset.type, { allowPrivate: this.allowPrivate });
      if (!validation.ok) {
        throw new ScanExecutionError(validation.reason);
      }

      const target = await resolveScanTarget(validation.value, validation.type, this.allowPrivate);
      const openPorts = scan.type === ScanType.PORT_SCAN ? [] : await this.openPortsHint(asset.id);

      await this.prisma.scan.update({
        where: { id: scanId },
        data: { targetAddress: target.address },
      });

      const startedAt = Date.now();
      const outcome = await scanner.run({
        scanId,
        organizationId: scan.organizationId,
        asset,
        target,
        allowPrivate: this.allowPrivate,
        openPorts,
        signal,
        timeoutMs,
      });

      if (abortReason(signal)) {
        await this.handleInterrupted(scanId, signal);
        return;
      }

      const persisted = await this.persistOutcome(scan, target.address, outcome, Date.now() - startedAt);
      if (!persisted) return;
      const { result: findings, opened } = persisted;
      this.logger.log(
        `Escaneo ${scanId} (${scan.type}): completado en ${((Date.now() - startedAt) / 1000).toFixed(1)} s, ` +
          `${outcome.findings.length} hallazgo(s) (${findings.created} nuevos, ${findings.resolved} resueltos)`,
      );

      // RF-10: alertas tempranas. Fuera de la transacción y sin propagar errores.
      await this.alerts.handleScanCompleted({
        organizationId: scan.organizationId,
        assetId: scan.assetId,
        scanId,
        scanType: scan.type,
        opened,
      });
    } catch (err) {
      if (abortReason(signal)) {
        await this.handleInterrupted(scanId, signal);
        return;
      }
      const controlled = err instanceof ScanExecutionError || err instanceof NmapParseError;
      const message = controlled ? (err as Error).message : 'Error interno durante el escaneo';
      if (controlled) {
        this.logger.warn(`Escaneo ${scanId}: ${message}`);
      } else {
        this.logger.error(`Escaneo ${scanId}: ${(err as Error).stack ?? String(err)}`);
      }
      await this.prisma.scan.updateMany({
        where: { id: scanId, status: ScanStatus.RUNNING },
        data: { status: ScanStatus.FAILED, finishedAt: new Date(), errorMessage: message },
      });
    } finally {
      this.cancellation.release(scanId);
    }
  }

  /**
   * Escaneo interrumpido: por apagado vuelve a la cola; por timeout se marca
   * FAILED; por cancelación del usuario el estado CANCELLED ya está guardado.
   */
  private async handleInterrupted(scanId: string, signal: AbortSignal): Promise<void> {
    const reason = abortReason(signal);
    if (reason === 'shutdown') {
      await this.prisma.scan.updateMany({
        where: { id: scanId, status: ScanStatus.RUNNING },
        data: { status: ScanStatus.PENDING, startedAt: null, targetAddress: null },
      });
      return;
    }
    if (reason === 'timeout') {
      this.logger.warn(`Escaneo ${scanId}: tiempo máximo excedido`);
      await this.prisma.scan.updateMany({
        where: { id: scanId, status: ScanStatus.RUNNING },
        data: {
          status: ScanStatus.FAILED,
          finishedAt: new Date(),
          errorMessage: `El escaneo superó el tiempo máximo permitido (${this.timeoutSeconds} s)`,
        },
      });
      return;
    }
    await this.prisma.scan.updateMany({
      where: { id: scanId, status: ScanStatus.RUNNING },
      data: { status: ScanStatus.CANCELLED, finishedAt: new Date() },
    });
  }

  private async persistOutcome(
    scan: { id: string; assetId: string; organizationId: string; type: ScanType; asset: { value: string } },
    targetAddress: string,
    outcome: ScanOutcome,
    durationMs: number,
  ): Promise<{ result: SyncFindingsResult; opened: OpenedFinding[] } | null> {
    const finishedAt = new Date();
    return this.prisma.$transaction(async (tx) => {
      // Si el usuario canceló mientras tanto, no se sobrescribe el estado.
      const updated = await tx.scan.updateMany({
        where: { id: scan.id, status: ScanStatus.RUNNING },
        data: { status: ScanStatus.COMPLETED, finishedAt, parameters: outcome.parameters as Prisma.InputJsonValue },
      });
      if (updated.count === 0) {
        return null;
      }

      if (outcome.ports && outcome.ports.length > 0) {
        await tx.scanPort.createMany({
          data: outcome.ports.map((p) => ({
            organizationId: scan.organizationId,
            scanId: scan.id,
            assetId: scan.assetId,
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

      const { result: findings, opened } = await this.findings.syncForScan(tx, {
        organizationId: scan.organizationId,
        assetId: scan.assetId,
        scanId: scan.id,
        scanType: scan.type,
        drafts: outcome.findings,
      });

      const summary = {
        target: scan.asset.value,
        targetAddress,
        durationSeconds: Math.round(durationMs / 100) / 10,
        ...outcome.summary,
        findings,
      };

      await tx.scan.update({
        where: { id: scan.id },
        data: {
          rawResult: outcome.rawResult as Prisma.InputJsonValue,
          summary: summary as unknown as Prisma.InputJsonValue,
          errorMessage: null,
        },
      });
      await tx.asset.update({ where: { id: scan.assetId }, data: { lastScannedAt: finishedAt } });

      // RF-07 / RF-11: nueva instantánea del Security Score del activo y de la organización.
      await this.riskScores.snapshot(tx, {
        organizationId: scan.organizationId,
        assetId: scan.assetId,
        trigger: RiskScoreTrigger.SCAN_COMPLETED,
        scanId: scan.id,
      });
      return { result: findings, opened };
    });
  }
}
