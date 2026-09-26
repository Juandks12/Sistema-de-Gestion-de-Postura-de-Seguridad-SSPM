import { Injectable, Logger, OnApplicationBootstrap, OnApplicationShutdown } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { MonitoringFrequency, Prisma, ScanSource } from '@prisma/client';
import { PrismaService } from '../prisma/prisma.service';
import { ScansService } from '../scans/scans.service';

const HOUR_MS = 60 * 60 * 1000;

/** Periodo de cada frecuencia de monitoreo. */
export const FREQUENCY_PERIOD_MS: Record<Exclude<MonitoringFrequency, 'OFF'>, number> = {
  DAILY: 24 * HOUR_MS,
  WEEKLY: 7 * 24 * HOUR_MS,
};

/**
 * Margen para que la auditoría no se retrase cada ciclo por la granularidad
 * del planificador (una auditoría diaria se considera vencida a las 23h50m).
 */
export const SCHEDULE_SLACK_MS = 10 * 60 * 1000;

/** Fecha a partir de la cual un activo con `last` vuelve a estar vencido. */
export function nextRunAt(last: Date | null, frequency: MonitoringFrequency, now: Date = new Date()): Date | null {
  if (frequency === MonitoringFrequency.OFF) return null;
  if (!last) return now;
  return new Date(last.getTime() + FREQUENCY_PERIOD_MS[frequency] - SCHEDULE_SLACK_MS);
}

export interface SchedulerRunResult {
  dueAssets: number;
  claimed: number;
  queuedScans: number;
  errors: number;
}

/**
 * Monitoreo continuo (sección 10.4): reencola la auditoría completa de cada
 * activo según la frecuencia configurada por su organización.
 *
 * Seguro con varias instancias: antes de encolar, cada activo se "reclama"
 * con un UPDATE condicional sobre `last_scheduled_scan_at`, de modo que solo
 * una instancia lo toma en cada ciclo. Los escaneos en curso se omiten.
 */
@Injectable()
export class MonitoringScheduler implements OnApplicationBootstrap, OnApplicationShutdown {
  private readonly logger = new Logger(MonitoringScheduler.name);
  private timer?: NodeJS.Timeout;
  private running = false;

  constructor(
    private readonly prisma: PrismaService,
    private readonly config: ConfigService,
    private readonly scans: ScansService,
  ) {}

  get enabled(): boolean {
    return this.config.get<boolean>('SCHEDULER_ENABLED') !== false;
  }

  private get batchSize(): number {
    return this.config.get<number>('SCHEDULER_BATCH_SIZE') ?? 20;
  }

  onApplicationBootstrap(): void {
    if (!this.enabled) {
      this.logger.log('Monitoreo continuo deshabilitado (SCHEDULER_ENABLED=false)');
      return;
    }
    const interval = this.config.get<number>('SCHEDULER_INTERVAL_MS') ?? 60000;
    this.timer = setInterval(() => void this.tick(), interval);
    this.timer.unref();
    this.logger.log(`Monitoreo continuo activo (revisión cada ${Math.round(interval / 1000)} s)`);
  }

  onApplicationShutdown(): void {
    if (this.timer) clearInterval(this.timer);
  }

  private async tick(): Promise<void> {
    if (this.running) return;
    this.running = true;
    try {
      const result = await this.runOnce();
      if (result.claimed > 0) {
        this.logger.log(
          `Monitoreo continuo: ${result.claimed} activo(s) reauditado(s), ${result.queuedScans} escaneo(s) encolado(s)`,
        );
      }
    } catch (err) {
      this.logger.error(`Error en el monitoreo continuo: ${(err as Error).message}`);
    } finally {
      this.running = false;
    }
  }

  /** Activos vencidos de una frecuencia, los más atrasados primero. */
  private dueWhere(frequency: Exclude<MonitoringFrequency, 'OFF'>, now: Date): Prisma.AssetWhereInput {
    const cutoff = new Date(now.getTime() - FREQUENCY_PERIOD_MS[frequency] + SCHEDULE_SLACK_MS);
    return {
      isActive: true,
      authorizationConfirmed: true,
      ...(this.config.get<boolean>('ASSET_VERIFICATION_REQUIRED') !== false ? { verifiedAt: { not: null } } : {}),
      organization: { isActive: true, monitoringFrequency: frequency },
      OR: [{ lastScheduledScanAt: null }, { lastScheduledScanAt: { lt: cutoff } }],
    };
  }

  /** Una pasada del planificador. Pública para poder invocarla en pruebas. */
  async runOnce(now: Date = new Date()): Promise<SchedulerRunResult> {
    const result: SchedulerRunResult = { dueAssets: 0, claimed: 0, queuedScans: 0, errors: 0 };
    let remaining = this.batchSize;

    for (const frequency of [MonitoringFrequency.DAILY, MonitoringFrequency.WEEKLY] as const) {
      if (remaining <= 0) break;
      const where = this.dueWhere(frequency, now);
      const due = await this.prisma.asset.findMany({
        where,
        select: { id: true, organizationId: true },
        orderBy: [{ lastScheduledScanAt: { sort: 'asc', nulls: 'first' } }, { createdAt: 'asc' }],
        take: remaining,
      });
      result.dueAssets += due.length;

      for (const asset of due) {
        remaining -= 1;
        // Reclamo atómico: si otra instancia ya lo tomó, count = 0.
        const claim = await this.prisma.asset.updateMany({
          where: { id: asset.id, ...where },
          data: { lastScheduledScanAt: now },
        });
        if (claim.count === 0) continue;
        result.claimed += 1;
        try {
          const { queued } = await this.scans.enqueueAll({
            organizationId: asset.organizationId,
            assetId: asset.id,
            requestedById: null,
            source: ScanSource.SCHEDULED,
          });
          result.queuedScans += queued.length;
        } catch (err) {
          result.errors += 1;
          this.logger.warn(`No se pudo reauditar el activo ${asset.id}: ${(err as Error).message}`);
        }
      }
    }
    return result;
  }
}
