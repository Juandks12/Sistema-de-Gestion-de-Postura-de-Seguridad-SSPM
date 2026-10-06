import { BadRequestException, Injectable, NotFoundException } from '@nestjs/common';
import { FindingCategory, FindingSeverity, FindingStatus, Prisma, RiskScoreTrigger, ScanType } from '@prisma/client';
import { createHash } from 'node:crypto';
import { Readable } from 'node:stream';
import { AuthUser } from '../common/interfaces/auth-user.interface';
import { AuditService } from '../audit/audit.service';
import { PrismaService } from '../prisma/prisma.service';
import { RiskScoresService } from '../risk/risk-scores.service';
import { UTF8_BOM, formatCsvRow } from '../common/utils/csv';
import { FindingDraft } from '../scans/scanner.interface';
import { ExportFindingsQuery } from './dto/export-findings.query';
import { ListFindingsQuery } from './dto/list-findings.query';
import { ReviewFindingDto } from './dto/review-finding.dto';
import { getRule } from './rules.catalog';

/** Categorías de hallazgo que produce cada tipo de escaneo. */
export const CATEGORIES_BY_SCAN_TYPE: Record<ScanType, FindingCategory[]> = {
  [ScanType.PORT_SCAN]: [FindingCategory.EXPOSED_SERVICE, FindingCategory.VULNERABLE_SOFTWARE],
  [ScanType.WEB_HEADERS]: [FindingCategory.HTTP_HEADERS],
  [ScanType.SSL_CERT]: [FindingCategory.TLS_CERTIFICATE],
  [ScanType.SENSITIVE_PATHS]: [FindingCategory.SENSITIVE_PATH],
  [ScanType.EMAIL_SECURITY]: [FindingCategory.EMAIL_SECURITY],
  // El descubrimiento de subdominios alimenta el inventario, no genera hallazgos.
  [ScanType.SUBDOMAIN_DISCOVERY]: [],
};

export interface SyncFindingsInput {
  organizationId: string;
  assetId: string;
  scanId: string;
  scanType: ScanType;
  drafts: FindingDraft[];
  /** Categorías que no se evaluaron por completo: sus hallazgos abiertos no se resuelven. */
  incompleteCategories?: FindingCategory[];
}

export interface SyncFindingsResult {
  created: number;
  updated: number;
  reopened: number;
  resolved: number;
  bySeverity: Record<FindingSeverity, number>;
}

/** Hallazgo que pasó a OPEN en este escaneo (nuevo o reabierto). Alimenta las alertas. */
export interface OpenedFinding {
  id: string;
  ruleId: string;
  category: FindingCategory;
  severity: FindingSeverity;
  title: string;
  location: string;
  evidence: Record<string, unknown>;
  reopened: boolean;
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
  assignedToId: true,
  dueDate: true,
  remediationNote: true,
  reviewNote: true,
  createdAt: true,
  updatedAt: true,
  asset: { select: { id: true, type: true, value: true, name: true } },
  reviewedBy: { select: { id: true, fullName: true, email: true } },
  assignedTo: { select: { id: true, fullName: true, email: true } },
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
  constructor(
    private readonly prisma: PrismaService,
    private readonly riskScores: RiskScoresService,
    private readonly audit: AuditService,
  ) {}

  /**
   * Sincroniza los hallazgos de un escaneo completado dentro de una transacción:
   * - crea los nuevos, actualiza los ya existentes (`last_seen_at`, evidencia),
   * - reabre los que estaban RESOLVED y vuelven a detectarse,
   * - marca RESOLVED los OPEN de la misma categoría que ya no se detectan.
   * Los hallazgos ACCEPTED o FALSE_POSITIVE conservan su estado.
   */
  async syncForScan(
    tx: Prisma.TransactionClient,
    input: SyncFindingsInput,
  ): Promise<{ result: SyncFindingsResult; opened: OpenedFinding[] }> {
    const now = new Date();
    const result: SyncFindingsResult = { created: 0, updated: 0, reopened: 0, resolved: 0, bySeverity: emptyCounts() };
    const opened: OpenedFinding[] = [];
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
        cvssScore: new Prisma.Decimal(draft.cvss ?? rule.cvss),
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

      const openedInfo = {
        ruleId: data.ruleId,
        category: data.category,
        severity,
        title: data.title,
        location: data.location,
        evidence: draft.evidence ?? {},
      };
      if (!existing) {
        const created = await tx.finding.create({
          data: { ...data, organizationId: input.organizationId, assetId: input.assetId, fingerprint, firstSeenAt: now },
          select: { id: true },
        });
        result.created += 1;
        opened.push({ id: created.id, ...openedInfo, reopened: false });
      } else if (existing.status === FindingStatus.RESOLVED) {
        await tx.finding.update({
          where: { id: existing.id },
          data: { ...data, status: FindingStatus.OPEN, resolvedAt: null },
        });
        result.reopened += 1;
        opened.push({ id: existing.id, ...openedInfo, reopened: true });
      } else {
        await tx.finding.update({ where: { id: existing.id }, data });
        result.updated += 1;
      }
      result.bySeverity[severity] += 1;
    }

    const incomplete = new Set(input.incompleteCategories ?? []);
    const categories = CATEGORIES_BY_SCAN_TYPE[input.scanType].filter((c) => !incomplete.has(c));
    if (categories.length === 0) return { result, opened };
    const resolved = await tx.finding.updateMany({
      where: {
        assetId: input.assetId,
        category: { in: categories },
        status: { in: [FindingStatus.OPEN, FindingStatus.IN_PROGRESS, FindingStatus.VERIFYING] },
        ...(seen.size > 0 ? { fingerprint: { notIn: [...seen] } } : {}),
      },
      data: { status: FindingStatus.RESOLVED, resolvedAt: now },
    });
    result.resolved = resolved.count;
    return { result, opened };
  }

  async findAll(organizationId: string, query: ListFindingsQuery) {
    const where: Prisma.FindingWhereInput = {
      organizationId,
      assetId: query.assetId,
      severity: query.severity,
      status: query.status,
      category: query.category,
      ...(query.assignedToId ? { assignedToId: query.assignedToId } : {}),
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
    const existing = await this.findOne(actor.organizationId, id);

    if (dto.assignedToId) {
      const assignedUser = await this.prisma.user.findFirst({
        where: { id: dto.assignedToId, organizationId: actor.organizationId },
        select: { id: true },
      });
      if (!assignedUser) {
        throw new BadRequestException('El usuario asignado no pertenece a la organización');
      }
    }

    const reviewed = await this.prisma.$transaction(async (tx) => {
      const updateData: Prisma.FindingUpdateInput = {};

      if (dto.status !== undefined) {
        updateData.status = dto.status;
        if (existing.status === FindingStatus.RESOLVED) {
          updateData.resolvedAt = null;
        }
      }

      if (dto.note !== undefined) {
        updateData.reviewNote = dto.note ? dto.note.trim() : null;
        updateData.reviewedBy = { connect: { id: actor.id } };
      } else if (dto.status && dto.status !== existing.status) {
        updateData.reviewedBy = { connect: { id: actor.id } };
      }

      if (dto.assignedToId !== undefined) {
        updateData.assignedTo = dto.assignedToId ? { connect: { id: dto.assignedToId } } : { disconnect: true };
      }

      if (dto.dueDate !== undefined) {
        updateData.dueDate = dto.dueDate ? new Date(dto.dueDate) : null;
      }

      if (dto.remediationNote !== undefined) {
        updateData.remediationNote = dto.remediationNote ? dto.remediationNote.trim() : null;
      }

      const updated = await tx.finding.update({
        where: { id },
        data: updateData,
        select: findingSelect,
      });

      // Aceptar un riesgo o descartar un falso positivo cambia el Security Score.
      if (dto.status && existing.status !== dto.status) {
        await this.riskScores.snapshot(tx, {
          organizationId: actor.organizationId,
          assetId: existing.assetId,
          trigger: RiskScoreTrigger.FINDING_REVIEWED,
        });
      }
      return updated;
    });

    this.audit.record({
      organizationId: actor.organizationId,
      action: 'finding.review',
      actor,
      target: { type: 'finding', id: reviewed.id, label: `${reviewed.ruleId} · ${reviewed.location}` },
      detail: {
        ...(dto.status ? { status: dto.status, previousStatus: existing.status } : {}),
        ...(dto.note ? { note: dto.note } : {}),
        ...(dto.assignedToId !== undefined ? { assignedToId: dto.assignedToId } : {}),
        ...(dto.dueDate !== undefined ? { dueDate: dto.dueDate } : {}),
        ...(dto.remediationNote !== undefined ? { remediationNote: dto.remediationNote } : {}),
      },
    });

    return reviewed;
  }

  /** Conteo de hallazgos abiertos por severidad y categoría (base del Security Score). */
  async summary(organizationId: string, assetId?: string) {
    const where: Prisma.FindingWhereInput = {
      organizationId,
      assetId,
      status: { in: [FindingStatus.OPEN, FindingStatus.IN_PROGRESS, FindingStatus.VERIFYING] },
    };
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

  /**
   * Genera un stream legible (Readable) en formato CSV con soporte para
   * grandes volúmenes de datos mediante lectura por lotes (batching) y RFC 4180.
   */
  exportStream(organizationId: string, query: ExportFindingsQuery): Readable {
    const from = query.fromDate ?? query.from;
    const to = query.toDate ?? query.to;

    const where: Prisma.FindingWhereInput = {
      organizationId,
      assetId: query.assetId,
      severity: query.severity,
      status: query.status,
      category: query.category,
      ...(query.assignedToId ? { assignedToId: query.assignedToId } : {}),
      ...(from || to
        ? {
            firstSeenAt: {
              ...(from ? { gte: new Date(from) } : {}),
              ...(to ? { lte: new Date(to) } : {}),
            },
          }
        : {}),
    };

    const prisma = this.prisma;
    const batchSize = 500;

    async function* generateRows() {
      yield UTF8_BOM;
      yield formatCsvRow([
        'id',
        'rule_id',
        'severity',
        'cvss_score',
        'category',
        'status',
        'title',
        'description',
        'recommendation',
        'asset_name',
        'asset_value',
        'asset_type',
        'location',
        'first_seen_at',
        'last_seen_at',
        'resolved_at',
        'assigned_to',
        'due_date',
        'remediation_note',
        'reviewed_by',
        'review_note',
      ]);

      let skip = 0;
      while (true) {
        const batch = await prisma.finding.findMany({
          where,
          select: {
            id: true,
            ruleId: true,
            severity: true,
            cvssScore: true,
            category: true,
            status: true,
            title: true,
            description: true,
            recommendation: true,
            location: true,
            firstSeenAt: true,
            lastSeenAt: true,
            resolvedAt: true,
            assignedTo: { select: { id: true, email: true, fullName: true } },
            dueDate: true,
            remediationNote: true,
            reviewNote: true,
            asset: { select: { id: true, name: true, value: true, type: true } },
            reviewedBy: { select: { id: true, email: true, fullName: true } },
          },
          orderBy: [{ status: 'asc' }, { cvssScore: 'desc' }, { lastSeenAt: 'desc' }, { id: 'asc' }],
          skip,
          take: batchSize,
        });

        if (batch.length === 0) break;

        for (const finding of batch) {
          yield formatCsvRow([
            finding.id,
            finding.ruleId,
            finding.severity,
            finding.cvssScore !== null ? Number(finding.cvssScore) : '',
            finding.category,
            finding.status,
            finding.title,
            finding.description,
            finding.recommendation,
            finding.asset?.name ?? '',
            finding.asset?.value ?? '',
            finding.asset?.type ?? '',
            finding.location,
            finding.firstSeenAt,
            finding.lastSeenAt,
            finding.resolvedAt ?? '',
            finding.assignedTo ? `${finding.assignedTo.fullName} (${finding.assignedTo.email})` : '',
            finding.dueDate ? finding.dueDate.toISOString() : '',
            finding.remediationNote ?? '',
            finding.reviewedBy?.email ?? '',
            finding.reviewNote ?? '',
          ]);
        }

        skip += batch.length;
        if (batch.length < batchSize) break;
      }
    }

    return Readable.from(generateRows());
  }
}
