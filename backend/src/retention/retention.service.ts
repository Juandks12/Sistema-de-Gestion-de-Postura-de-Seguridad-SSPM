import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { ScanStatus } from '@prisma/client';
import { AuditService } from '../audit/audit.service';
import { AuthUser } from '../common/interfaces/auth-user.interface';
import { PrismaService } from '../prisma/prisma.service';

export interface RetentionResult {
  executedAt: string;
  triggeredBy: string;
  scansPurged: number;
  scanPortsPurged: number;
  tokensPurged: number;
  loginAttemptsPurged: number;
  auditLogsPurged: number;
  reportsPurged: number;
}

export interface RetentionStatus {
  enabled: boolean;
  scansRetentionDays: number;
  auditRetentionDays: number;
  tokensRetentionDays: number;
  reportsRetentionDays: number;
  lastRunAt: string | null;
  lastResult: RetentionResult | null;
}

/**
 * Servicio de retención de datos y purga de registros históricos.
 * Evita el crecimiento descontrolado de la base de datos protegiendo
 * siempre los hallazgos abiertos y el último escaneo de cada activo.
 */
@Injectable()
export class RetentionService {
  private readonly logger = new Logger(RetentionService.name);
  private lastRunAt: string | null = null;
  private lastResult: RetentionResult | null = null;

  constructor(
    private readonly prisma: PrismaService,
    private readonly config: ConfigService,
    private readonly audit: AuditService,
  ) {}

  get enabled(): boolean {
    return this.config.get<boolean>('RETENTION_ENABLED') !== false;
  }

  get scansDays(): number {
    return this.config.get<number>('RETENTION_SCANS_DAYS') ?? 90;
  }

  get auditDays(): number {
    return this.config.get<number>('RETENTION_AUDIT_DAYS') ?? 365;
  }

  get tokensDays(): number {
    return this.config.get<number>('RETENTION_TOKENS_DAYS') ?? 30;
  }

  get reportsDays(): number {
    return this.config.get<number>('RETENTION_REPORTS_DAYS') ?? 180;
  }

  getStatus(): RetentionStatus {
    return {
      enabled: this.enabled,
      scansRetentionDays: this.scansDays,
      auditRetentionDays: this.auditDays,
      tokensRetentionDays: this.tokensDays,
      reportsRetentionDays: this.reportsDays,
      lastRunAt: this.lastRunAt,
      lastResult: this.lastResult,
    };
  }

  async runRetention(actor?: AuthUser | null, now: Date = new Date()): Promise<RetentionResult> {
    const executedAt = now.toISOString();
    const triggeredBy = actor ? actor.email : 'scheduler';

    const result: RetentionResult = {
      executedAt,
      triggeredBy,
      scansPurged: 0,
      scanPortsPurged: 0,
      tokensPurged: 0,
      loginAttemptsPurged: 0,
      auditLogsPurged: 0,
      reportsPurged: 0,
    };

    if (!this.enabled) {
      this.logger.log('Purga de retención de datos omitida: RETENTION_ENABLED=false');
      return result;
    }

    try {
      // 1. Escaneos completados/fallidos antiguos (protegiendo el más reciente de cada activo)
      if (this.scansDays > 0) {
        const cutoffScans = new Date(now.getTime() - this.scansDays * 24 * 60 * 60 * 1000);
        const latestScans = await this.prisma.scan.findMany({
          distinct: ['assetId'],
          orderBy: { createdAt: 'desc' },
          select: { id: true },
        });
        const protectedIds = new Set(latestScans.map((s) => s.id));

        const candidates = await this.prisma.scan.findMany({
          where: {
            createdAt: { lt: cutoffScans },
            status: { in: [ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED] },
          },
          select: { id: true },
        });

        const toDeleteIds = candidates.map((s) => s.id).filter((id) => !protectedIds.has(id));

        if (toDeleteIds.length > 0) {
          const portsCount = await this.prisma.scanPort.count({
            where: { scanId: { in: toDeleteIds } },
          });
          const deleteResult = await this.prisma.scan.deleteMany({
            where: { id: { in: toDeleteIds } },
          });
          result.scansPurged = deleteResult.count;
          result.scanPortsPurged = portsCount;
        }
      }

      // 2. Tokens de un solo uso expirados o ya consumidos
      if (this.tokensDays > 0) {
        const cutoffTokens = new Date(now.getTime() - this.tokensDays * 24 * 60 * 60 * 1000);
        const deleteTokens = await this.prisma.accountToken.deleteMany({
          where: {
            OR: [
              { expiresAt: { lt: cutoffTokens } },
              { usedAt: { not: null, lt: cutoffTokens } },
            ],
          },
        });
        result.tokensPurged = deleteTokens.count;
      }

      // 3. Intentos fallidos de login antiguos sin bloqueo activo
      const cutoffLogins = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
      const deleteLogins = await this.prisma.loginAttempt.deleteMany({
        where: {
          updatedAt: { lt: cutoffLogins },
          OR: [{ lockedUntil: null }, { lockedUntil: { lt: now } }],
        },
      });
      result.loginAttemptsPurged = deleteLogins.count;

      // 4. Reportes PDF generados antiguos
      if (this.reportsDays > 0) {
        const cutoffReports = new Date(now.getTime() - this.reportsDays * 24 * 60 * 60 * 1000);
        const deleteReports = await this.prisma.report.deleteMany({
          where: { createdAt: { lt: cutoffReports } },
        });
        result.reportsPurged = deleteReports.count;
      }

      // 5. Registros de auditoría antiguos
      if (this.auditDays > 0) {
        const cutoffAudit = new Date(now.getTime() - this.auditDays * 24 * 60 * 60 * 1000);
        const deleteAudit = await this.prisma.auditLog.deleteMany({
          where: { createdAt: { lt: cutoffAudit } },
        });
        result.auditLogsPurged = deleteAudit.count;
      }

      this.lastRunAt = executedAt;
      this.lastResult = result;

      this.logger.log(
        `Purga de retención completada: ${result.scansPurged} escaneos, ${result.tokensPurged} tokens, ${result.auditLogsPurged} auditorías eliminadas`,
      );

      if (actor) {
        this.audit.record({
          organizationId: actor.organizationId,
          action: 'system.retention_cleanup',
          actor,
          target: { type: 'system', id: 'retention', label: 'Política de retención de datos' },
          detail: {
            scansPurged: result.scansPurged,
            scanPortsPurged: result.scanPortsPurged,
            tokensPurged: result.tokensPurged,
            loginAttemptsPurged: result.loginAttemptsPurged,
            auditLogsPurged: result.auditLogsPurged,
            reportsPurged: result.reportsPurged,
          },
        });
      }

      return result;
    } catch (err) {
      this.logger.error(`Error durante la purga de retención de datos: ${(err as Error).message}`);
      throw err;
    }
  }
}
