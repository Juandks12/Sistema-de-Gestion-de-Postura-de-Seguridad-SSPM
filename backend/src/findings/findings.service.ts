import { Injectable, NotFoundException } from '@nestjs/common';
import { FindingCategory, FindingSeverity, FindingStatus, Prisma, ScanType } from '@prisma/client';
import { createHash } from 'node:crypto';
import { AuthUser } from '../common/interfaces/auth-user.interface';
import { PrismaService } from '../prisma/prisma.service';
import { FindingDraft } from '../scans/scanner.interface';
import { ListFindingsQuery } from './dto/list-findings.query';
import { ReviewFindingDto } from './dto/review-finding.dto';
import { getRule } from './rules.catalog';

/** Categorías de hallazgo que produce cada tipo de escaneo. */
export const CATEGORIES_BY_SCAN_TYPE: Record<ScanType, FindingCategory[]> = {
  [ScanType.PORT_SCAN]: [FindingCategory.EXPOSED_SERVICE],
  [ScanType.WEB_HEADERS]: [FindingCategory.HTTP_HEADERS],
  [ScanType.SSL_CERT]: [FindingCategory.TLS_CERTIFICATE],
  [ScanType.SENSITIVE_PATHS]: [FindingCategory.SENSITIVE_PATH],
};

export interface SyncFindingsInput {
  organizationId: string;
  assetId: string;
  scanId: string;
  scanType: ScanType;
  drafts: FindingDraft[];
}

export interface SyncFindingsResult {
  created: number;
  updated: number;
  reopened: number;
  resolved: number;
  bySeverity: Record<FindingSeverity, number>;
}

const findingSelect = {
  id: true,
  organizationId: true,
  assetId: true,
  lastScanId: true,
  category: true,
  ruleId: true,
  severity: true,
  cvssScore: true,
  status: true,
  title: true,
  description: true,
  recommendation: true,
  location: true,
  evidence: true,
  firstSeenAt: true,
  lastSeenAt: true,
  resolvedAt: true,
  reviewNote: true,
  createdAt: true,
  updatedAt: true,
  asset: { select: { id: true, type: true, value: true, name: true } },
  reviewedBy: { select: { id: true, fullName: true, email: true } },
} satisfies Prisma.FindingSelect;

export function fingerprintOf(ruleId: string, location: string): string {
  return createHash('sha256').update(`${ruleId}|${location}`).digest('hex');
}

const SEVERITY_ORDER: FindingSeverity[] = [
  FindingSeverity.CRITICAL,
  FindingSeverity.HIGH,
  FindingSeverity.MEDIUM,
  FindingSeverity.LOW,
  FindingSeverity.INFO,
];

function emptyCounts(): Record<FindingSeverity, number> {
  return { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
}

/**
 * Gestión de hallazgos (RF-08): deduplicación entre escaneos, ciclo de vida
 * y consultas aisladas por organización.
 */
@Injectable()
export class FindingsService {
  constructor(private readonly prisma: PrismaService) {}

  /**
   * Sincroniza los hallazgos de un escaneo completado dentro de una transacción:
   * - crea los nuevos, actualiza los ya existentes (`last_seen_at`, evidencia),
   * - reabre los que estaban RESOLVED y vuelven a detectarse,
   * - marca RESOLVED los OPEN de la misma categoría que ya no se detectan.
   * Los hallazgos ACCEPTED o FALSE_POSITIVE conservan su estado.
   */
  async syncForScan(tx: Prisma.TransactionClient, input: SyncFindingsInput): Promise<SyncFindingsResult> {
    const now = new Date();
    const result: SyncFindingsResult = { created: 0, updated: 0, reopened: 0, resolved: 0, bySeverity: emptyCounts() };
    const seen = new Set<string>();

    for (const draft of input.drafts) {
      const rule = getRule(draft.ruleId);
      const fingerprint = fingerprintOf(draft.ruleId, draft.location);
      if (seen.has(fingerprint)) continue;
      seen.add(fingerprint);

      const severity = draft.severity ?? rule.severity;
      const data = {
        category: rule.category,
        ruleId: rule.id,
        severity,
        cvssScore: new Prisma.Decimal(rule.cvss),
        title: (draft.title ?? rule.title).slice(0, 200),
        description: draft.description ?? rule.description,
        recommendation: draft.recommendation ?? rule.recommendation,
        location: draft.location.slice(0, 500),
        evidence: (draft.evidence ?? {}) as Prisma.InputJsonValue,
        lastSeenAt: now,
        lastScanId: input.scanId,
      };

      const existing = await tx.finding.findUnique({
        where: { assetId_fingerprint: { assetId: input.assetId, fingerprint } },
        select: { id: true, status: true },
      });

      if (!existing) {
        await tx.finding.create({
          data: { ...data, organizationId: input.organizationId, assetId: input.assetId, fingerprint, firstSeenAt: now },
        });
        result.created += 1;
      } else if (existing.status === FindingStatus.RESOLVED) {
        await tx.finding.update({
          where: { id: existing.id },
          data: { ...data, status: FindingStatus.OPEN, resolvedAt: null },
        });
        result.reopened += 1;
      } else {
        await tx.finding.update({ where: { id: existing.id }, data });
        result.updated += 1;
      }
      result.bySeverity[severity] += 1;
    }

    const categories = CATEGORIES_BY_SCAN_TYPE[input.scanType];
    const resolved = await tx.finding.updateMany({
      where: {
        assetId: input.assetId,
        category: { in: categories },
        status: FindingStatus.OPEN,
        ...(seen.size > 0 ? { fingerprint: { notIn: [...seen] } } : {}),
      },
      data: { status: FindingStatus.RESOLVED, resolvedAt: now },
    });
    result.resolved = resolved.count;
    return result;
  }

  async findAll(organizationId: string, query: ListFindingsQuery) {
    const where: Prisma.FindingWhereInput = {
      organizationId,
      assetId: query.assetId,
      severity: query.severity,
      status: query.status,
      category: query.category,
    };
    const [items, total] = await this.prisma.$transaction([
      this.prisma.finding.findMany({
        where,
        select: findingSelect,
        orderBy: [{ status: 'asc' }, { cvssScore: 'desc' }, { lastSeenAt: 'desc' }],
        skip: (query.page - 1) * query.pageSize,
        take: query.pageSize,
      }),
      this.prisma.finding.count({ where }),
    ]);
    return {
      items,
      meta: { total, page: query.page, pageSize: query.pageSize, totalPages: Math.max(1, Math.ceil(total / query.pageSize)) },
    };
  }

  async findOne(organizationId: string, id: string) {
    const finding = await this.prisma.finding.findFirst({ where: { id, organizationId }, select: findingSelect });
    if (!finding) {
      throw new NotFoundException('Hallazgo no encontrado');
    }
    return finding;
  }

  async review(actor: AuthUser, id: string, dto: ReviewFindingDto) {
    await this.findOne(actor.organizationId, id);
    return this.prisma.finding.update({
      where: { id },
      data: { status: dto.status, reviewNote: dto.note ?? null, reviewedById: actor.id },
      select: findingSelect,
    });
  }

  /** Conteo de hallazgos abiertos por severidad y categoría (base del Security Score). */
  async summary(organizationId: string, assetId?: string) {
    const where: Prisma.FindingWhereInput = { organizationId, assetId, status: FindingStatus.OPEN };
    const [bySeverityRows, byCategoryRows, total] = await Promise.all([
      this.prisma.finding.groupBy({ by: ['severity'], where, _count: { id: true } }),
      this.prisma.finding.groupBy({ by: ['category'], where, _count: { id: true } }),
      this.prisma.finding.count({ where }),
    ]);
    const bySeverity = emptyCounts();
    for (const row of bySeverityRows) bySeverity[row.severity] = row._count.id;
    const byCategory: Record<string, number> = {};
    for (const row of byCategoryRows) byCategory[row.category] = row._count.id;
    return { total, bySeverity, byCategory, severityOrder: SEVERITY_ORDER };
  }
}
