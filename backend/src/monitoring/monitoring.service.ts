import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { MonitoringFrequency, ScanSource } from '@prisma/client';
import { AuditService } from '../audit/audit.service';
import { AuthUser } from '../common/interfaces/auth-user.interface';
import { PrismaService } from '../prisma/prisma.service';
import { FREQUENCY_PERIOD_MS, nextRunAt } from './monitoring.scheduler';

@Injectable()
export class MonitoringService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
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
        select: {
          id: true,
          value: true,
          name: true,
          isActive: true,
          authorizationConfirmed: true,
          verifiedAt: true,
          lastScheduledScanAt: true,
          lastScannedAt: true,
        },
      }),
      this.prisma.scan.findFirst({
        where: { organizationId, source: ScanSource.SCHEDULED },
        orderBy: { createdAt: 'desc' },
        select: { createdAt: true },
      }),
    ]);
    const frequency = org.monitoringFrequency;
    const now = new Date();
    const verificationRequired = this.config.get<boolean>('ASSET_VERIFICATION_REQUIRED') !== false;
    return {
      frequency,
      periodHours: frequency === MonitoringFrequency.OFF ? null : FREQUENCY_PERIOD_MS[frequency] / 3600000,
      schedulerEnabled: this.config.get<boolean>('SCHEDULER_ENABLED') !== false,
      lastScheduledScanAt: lastScheduled?.createdAt ?? null,
      assets: assets.map((a) => {
        const monitored =
          frequency !== MonitoringFrequency.OFF &&
          a.isActive &&
          a.authorizationConfirmed &&
          (!verificationRequired || a.verifiedAt !== null);
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

  async update(actor: AuthUser, frequency: MonitoringFrequency) {
    const previous = await this.prisma.organization.findUniqueOrThrow({
      where: { id: actor.organizationId },
      select: { monitoringFrequency: true },
    });
    await this.prisma.organization.update({
      where: { id: actor.organizationId },
      data: { monitoringFrequency: frequency },
    });
    if (previous.monitoringFrequency !== frequency) {
      this.audit.record({
        organizationId: actor.organizationId,
        action: 'monitoring.update',
        actor,
        detail: { frequency, previous: previous.monitoringFrequency },
      });
    }
    return this.status(actor.organizationId);
  }
}
