import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { MonitoringFrequency, ScanSource } from '@prisma/client';
import { PrismaService } from '../prisma/prisma.service';
import { FREQUENCY_PERIOD_MS, nextRunAt } from './monitoring.scheduler';

@Injectable()
export class MonitoringService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly config: ConfigService,
  ) {}

  /** Configuración del monitoreo continuo y próxima auditoría de cada activo. */
  async status(organizationId: string) {
    const org = await this.prisma.organization.findUniqueOrThrow({
      where: { id: organizationId },
      select: { monitoringFrequency: true },
    });
    const [assets, lastScheduled] = await Promise.all([
      this.prisma.asset.findMany({
        where: { organizationId },
        orderBy: { createdAt: 'asc' },
        select: { id: true, value: true, name: true, isActive: true, authorizationConfirmed: true, lastScheduledScanAt: true, lastScannedAt: true },
      }),
      this.prisma.scan.findFirst({
        where: { organizationId, source: ScanSource.SCHEDULED },
        orderBy: { createdAt: 'desc' },
        select: { createdAt: true },
      }),
    ]);
    const frequency = org.monitoringFrequency;
    const now = new Date();
    return {
      frequency,
      periodHours: frequency === MonitoringFrequency.OFF ? null : FREQUENCY_PERIOD_MS[frequency] / 3600000,
      schedulerEnabled: this.config.get<boolean>('SCHEDULER_ENABLED') !== false,
      lastScheduledScanAt: lastScheduled?.createdAt ?? null,
      assets: assets.map((a) => {
        const monitored = frequency !== MonitoringFrequency.OFF && a.isActive && a.authorizationConfirmed;
        const next = monitored ? nextRunAt(a.lastScheduledScanAt, frequency, now) : null;
        return {
          ...a,
          monitored,
          nextRunAt: next,
          /** Vencido: el planificador lo tomará en su próxima revisión. */
          due: next !== null && next.getTime() <= now.getTime(),
        };
      }),
    };
  }

  async update(organizationId: string, frequency: MonitoringFrequency) {
    await this.prisma.organization.update({ where: { id: organizationId }, data: { monitoringFrequency: frequency } });
    return this.status(organizationId);
  }
}
