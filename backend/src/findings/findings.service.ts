import { BadRequestException, Injectable, NotFoundException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AssetType, FindingCategory, FindingSeverity, FindingStatus, Prisma, RiskScoreTrigger, ScanType } from '@prisma/client';
import { createHash } from 'node:crypto';
import { isIP } from 'node:net';
import { Readable } from 'node:stream';
import { AuditService } from '../audit/audit.service';
import { createDnsClient } from '../common/dns/dns-client';
import { AuthUser } from '../common/interfaces/auth-user.interface';
import { formatCsvRow, UTF8_BOM } from '../common/utils/csv';
import { PrismaService } from '../prisma/prisma.service';
import { RiskScoresService } from '../risk/risk-scores.service';
import { analyzeHeaders } from '../scans/analyzers/headers.analyzer';
import { analyzeTls } from '../scans/analyzers/tls.analyzer';
import { analyzeEmailSecurity } from '../scans/email/email-security.analyzer';
import { FindingDraft } from '../scans/scanner.interface';
import { resolveScanTarget } from '../scans/target-resolver';
import { httpProbe, HttpProbeOutcome } from '../scans/web/http-client';
import { SENSITIVE_PATHS } from '../scans/web/sensitive-paths.catalog';
import { tcpPortOpen, tlsProbe } from '../scans/web/tls-probe';
import { ExportFindingsQuery } from './dto/export-findings.query';
import { ListFindingsQuery } from './dto/list-findings.query';
import { ReviewFindingDto } from './dto/review-finding.dto';
import { CreateManualFindingDto } from './dto/create-manual-finding.dto';
import { BulkReviewFindingsDto } from './dto/bulk-review-findings.dto';
import { FINDING_RULES, getRule, RemediationEffort } from './rules.catalog';
import { getRemediationGuide, RemediationGuide } from './remediation.catalog';
import { CSPM_RULES_MAP } from '../cloud/cspm.catalog';
import { ComplianceFramework } from '../compliance/compliance.catalog';
import {
  computeDefaultFindingDueDate,
  FindingComplianceControlRef,
  FindingSourceType,
  getRuleIdsForFramework,
  resolveComplianceControls,
  resolveFindingSource,
  resolveSecurityTaxonomy,
} from './grc-taxonomy.catalog';

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

export const CLOUD_FINDING_CATEGORIES: FindingCategory[] = [
  FindingCategory.CLOUD_IAM,
  FindingCategory.CLOUD_STORAGE,
  FindingCategory.CLOUD_NETWORK,
  FindingCategory.CLOUD_COMPUTE,
  FindingCategory.CLOUD_DATABASE,
  FindingCategory.CLOUD_LOGGING,
];

export const PERIMETER_FINDING_CATEGORIES: FindingCategory[] = [
  FindingCategory.EXPOSED_SERVICE,
  FindingCategory.HTTP_HEADERS,
  FindingCategory.TLS_CERTIFICATE,
  FindingCategory.SENSITIVE_PATH,
  FindingCategory.VULNERABLE_SOFTWARE,
  FindingCategory.EMAIL_SECURITY,
];

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
  cloudAccountId: true,
  cloudResourceId: true,
  createdAt: true,
  updatedAt: true,
  asset: { select: { id: true, type: true, value: true, name: true } },
  reviewedBy: { select: { id: true, fullName: true, email: true } },
  assignedTo: { select: { id: true, fullName: true, email: true } },
  cloudAccount: { select: { id: true, provider: true, name: true, accountOrSubscriptionId: true } },
  cloudResource: { select: { id: true, provider: true, resourceType: true, nativeId: true, name: true, region: true } },
} satisfies Prisma.FindingSelect;

export type FindingRow = Prisma.FindingGetPayload<{ select: typeof findingSelect }>;

export interface RetestFindingResult {
  finding: FindingRow;
  stillReproducible: boolean;
  message: string;
  testedAt: string;
  details?: Record<string, unknown>;
}

export function fingerprintOf(ruleId: string, location: string): string {
  return createHash('sha256').update(`${ruleId}|${location}`).digest('hex');
}

export type SlaStatus = 'OVERDUE' | 'APPROACHING' | 'ON_TRACK' | 'RESOLVED' | 'NO_SLA';

export interface FindingSla {
  status: SlaStatus;
  hoursRemaining: number | null;
  isOverdue: boolean;
  isApproaching: boolean;
  dueDate: string | null;
  label: string;
}

export function computeSla(dueDate: Date | null, status: FindingStatus): FindingSla {
  if (status === FindingStatus.RESOLVED || status === FindingStatus.ACCEPTED || status === FindingStatus.FALSE_POSITIVE) {
    return {
      status: 'RESOLVED',
      hoursRemaining: null,
      isOverdue: false,
      isApproaching: false,
      dueDate: dueDate ? dueDate.toISOString() : null,
      label: 'Cerrado',
    };
  }

  if (!dueDate) {
    return {
      status: 'NO_SLA',
      hoursRemaining: null,
      isOverdue: false,
      isApproaching: false,
      dueDate: null,
      label: 'Sin SLA',
    };
  }

  const now = Date.now();
  const dueTime = dueDate.getTime();
  const diffHours = Math.round((dueTime - now) / (1000 * 60 * 60));

  if (diffHours < 0) {
    const overdueDays = Math.max(1, Math.ceil(Math.abs(diffHours) / 24));
    return {
      status: 'OVERDUE',
      hoursRemaining: diffHours,
      isOverdue: true,
      isApproaching: false,
      dueDate: dueDate.toISOString(),
      label: overdueDays === 1 ? 'Vencido hace 1 día' : `Vencido hace ${overdueDays} días`,
    };
  }

  if (diffHours <= 48) {
    return {
      status: 'APPROACHING',
      hoursRemaining: diffHours,
      isOverdue: false,
      isApproaching: true,
      dueDate: dueDate.toISOString(),
      label: diffHours <= 1 ? 'Vence en <1 hora' : `Vence en ${diffHours} horas`,
    };
  }

  const daysRemaining = Math.max(1, Math.ceil(diffHours / 24));
  return {
    status: 'ON_TRACK',
    hoursRemaining: diffHours,
    isOverdue: false,
    isApproaching: false,
    dueDate: dueDate.toISOString(),
    label: `${daysRemaining} días restantes`,
  };
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
    private readonly config?: ConfigService,
  ) {}

  private get allowPrivate(): boolean {
    return this.config?.get<boolean>('ALLOW_PRIVATE_TARGETS') === true;
  }

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

  /**
   * Enriquece una fila de hallazgo con metadatos de SLA, esfuerzo, impacto de negocio,
   * taxonomía técnica (CWE, OWASP Top 10, MITRE ATT&CK), origen unificado y controles GRC.
   */
  public enrichFinding(f: FindingRow) {
    const rule = FINDING_RULES.get(f.ruleId);
    const cspmRule = CSPM_RULES_MAP.get(f.ruleId);
    const ev =
      f.evidence && typeof f.evidence === 'object' && !Array.isArray(f.evidence)
        ? (f.evidence as Record<string, unknown>)
        : {};

    const taxonomy = resolveSecurityTaxonomy(f.ruleId, f.category, f.evidence);
    const complianceControls: FindingComplianceControlRef[] = resolveComplianceControls(f.ruleId, f.evidence);
    const sourceType: FindingSourceType = resolveFindingSource({
      ruleId: f.ruleId,
      category: f.category,
      cloudAccountId: f.cloudAccountId,
      evidence: f.evidence,
    });

    const customEffort = typeof ev.effort === 'string' ? (ev.effort as RemediationEffort) : undefined;
    const customImpact = typeof ev.businessImpact === 'string' ? ev.businessImpact : undefined;
    const customCli = typeof ev.remediationCli === 'string' ? ev.remediationCli : undefined;
    const customIac = typeof ev.remediationIac === 'string' ? ev.remediationIac : undefined;

    return {
      ...f,
      sla: computeSla(f.dueDate, f.status),
      remediationGuide: getRemediationGuide(f.ruleId, f.recommendation),
      effort: customEffort ?? rule?.effort ?? 'MODERATE',
      estimatedMinutes: rule?.estimatedMinutes ?? 60,
      businessImpact: customImpact ?? rule?.businessImpact ?? null,
      sourceType,
      cweId: taxonomy.cweId,
      owaspCategory: taxonomy.owaspCategory,
      mitreAttackTechnique: taxonomy.mitreAttackTechnique,
      complianceControls,
      remediationCli: customCli ?? cspmRule?.remediationCli ?? null,
      remediationIac: customIac ?? cspmRule?.remediationIac ?? null,
    };
  }

  private applyAdvancedWhere(
    where: Prisma.FindingWhereInput,
    query: {
      domain?: 'perimeter' | 'cloud' | 'manual' | 'threat';
      sourceType?: FindingSourceType;
      framework?: ComplianceFramework;
      controlCode?: string;
      search?: string;
      category?: FindingCategory;
    },
  ): void {
    const effectiveSource =
      query.sourceType ??
      (query.domain === 'cloud'
        ? 'CLOUD_CSPM'
        : query.domain === 'perimeter'
          ? 'PERIMETER_SCAN'
          : query.domain === 'manual'
            ? 'MANUAL_AUDIT'
            : query.domain === 'threat'
              ? 'THREAT_MALWARE_LAB'
              : undefined);

    if (!query.category && effectiveSource) {
      if (effectiveSource === 'CLOUD_CSPM') {
        where.category = { in: CLOUD_FINDING_CATEGORIES };
      } else if (effectiveSource === 'PERIMETER_SCAN') {
        where.category = { in: PERIMETER_FINDING_CATEGORIES };
        where.NOT = { ruleId: { startsWith: 'MANUAL-' } };
      } else if (effectiveSource === 'MANUAL_AUDIT') {
        where.ruleId = { startsWith: 'MANUAL-' };
      } else if (effectiveSource === 'THREAT_MALWARE_LAB') {
        where.OR = [
          { ruleId: { startsWith: 'THREAT-' } },
          { ruleId: { startsWith: 'MALWARE-' } },
        ];
      }
    }

    if (query.framework) {
      const frameworkRuleIds = getRuleIdsForFramework(query.framework, query.controlCode);
      where.ruleId = { in: frameworkRuleIds };
    }

    if (query.search && query.search.trim().length > 0) {
      const q = query.search.trim();
      where.AND = [
        ...(Array.isArray(where.AND) ? where.AND : where.AND ? [where.AND] : []),
        {
          OR: [
            { title: { contains: q, mode: 'insensitive' } },
            { ruleId: { contains: q, mode: 'insensitive' } },
            { location: { contains: q, mode: 'insensitive' } },
            { description: { contains: q, mode: 'insensitive' } },
          ],
        },
      ];
    }
  }

  async findAll(organizationId: string, query: ListFindingsQuery) {
    const where: Prisma.FindingWhereInput = {
      organizationId,
      assetId: query.assetId,
      cloudAccountId: query.cloudAccountId,
      severity: query.severity,
      status: query.status,
      category: query.category,
    };

    this.applyAdvancedWhere(where, query);

    if (query.assignedToId) {
      if (query.assignedToId === 'unassigned') {
        where.assignedToId = null;
      } else {
        where.assignedToId = query.assignedToId;
      }
    }

    if (query.slaStatus) {
      const now = new Date();
      const in48h = new Date(now.getTime() + 48 * 60 * 60 * 1000);
      const openStatuses: FindingStatus[] = [
        FindingStatus.OPEN,
        FindingStatus.IN_PROGRESS,
        FindingStatus.VERIFYING,
      ];

      if (query.slaStatus === 'OVERDUE') {
        where.status = query.status ?? { in: openStatuses };
        where.dueDate = { lt: now };
      } else if (query.slaStatus === 'APPROACHING') {
        where.status = query.status ?? { in: openStatuses };
        where.dueDate = { gte: now, lte: in48h };
      } else if (query.slaStatus === 'ON_TRACK') {
        where.status = query.status ?? { in: openStatuses };
        where.dueDate = { gt: in48h };
      } else if (query.slaStatus === 'NO_SLA') {
        where.status = query.status ?? { in: openStatuses };
        where.dueDate = null;
      }
    }

    if (query.effortLevel) {
      const matchingRuleIds = [...FINDING_RULES.values()]
        .filter((r) => r.effort === query.effortLevel)
        .map((r) => r.id);
      where.ruleId = { in: matchingRuleIds };
    }

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
    const enrichedItems = items.map((f) => this.enrichFinding(f));
    return {
      items: enrichedItems,
      meta: { total, page: query.page, pageSize: query.pageSize, totalPages: Math.max(1, Math.ceil(total / query.pageSize)) },
    };
  }

  async findOne(organizationId: string, id: string) {
    const finding = await this.prisma.finding.findFirst({ where: { id, organizationId }, select: findingSelect });
    if (!finding) {
      throw new NotFoundException('Hallazgo no encontrado');
    }
    return this.enrichFinding(finding);
  }

  async getRemediation(organizationId: string, id: string): Promise<RemediationGuide> {
    const finding = await this.findOne(organizationId, id);
    return finding.remediationGuide;
  }

  /**
   * Registro unificado de hallazgos manuales, pentesting externo, auditorías normativas o laboratorio.
   */
  async createManual(actor: AuthUser, dto: CreateManualFindingDto) {
    const asset = await this.prisma.asset.findFirst({
      where: { id: dto.assetId, organizationId: actor.organizationId },
      select: { id: true, name: true, value: true },
    });
    if (!asset) {
      throw new NotFoundException('El activo seleccionado no existe en la organización');
    }

    if (dto.assignedToId) {
      const assignedUser = await this.prisma.user.findFirst({
        where: { id: dto.assignedToId, organizationId: actor.organizationId },
        select: { id: true },
      });
      if (!assignedUser) {
        throw new BadRequestException('El usuario asignado no pertenece a la organización');
      }
    }

    const defaultCvssBySeverity: Record<FindingSeverity, number> = {
      CRITICAL: 9.5,
      HIGH: 7.8,
      MEDIUM: 5.5,
      LOW: 3.1,
      INFO: 0.0,
    };

    const normalizedRuleId = dto.ruleId?.trim()
      ? dto.ruleId.trim().toUpperCase().startsWith('MANUAL-')
        ? dto.ruleId.trim().toUpperCase()
        : `MANUAL-${dto.ruleId.trim().toUpperCase()}`
      : `MANUAL-${dto.category}-${createHash('sha1').update(`${dto.title}|${dto.location}`).digest('hex').slice(0, 6).toUpperCase()}`;

    const fingerprint = fingerprintOf(normalizedRuleId, dto.location.trim());
    const now = new Date();
    const dueDate = dto.dueDate ? new Date(dto.dueDate) : computeDefaultFindingDueDate(dto.severity, now);
    const cvss = dto.cvssScore ?? defaultCvssBySeverity[dto.severity];

    const evidencePayload: Record<string, unknown> = {
      ...(dto.evidence ?? {}),
      sourceType: 'MANUAL_AUDIT',
      manualAudit: true,
      createdByEmail: actor.email,
      createdByName: actor.fullName,
      ...(dto.cweId ? { cweId: dto.cweId.trim() } : {}),
      ...(dto.owaspCategory ? { owaspCategory: dto.owaspCategory.trim() } : {}),
      ...(dto.mitreAttackTechnique ? { mitreAttackTechnique: dto.mitreAttackTechnique.trim() } : {}),
      ...(dto.complianceControlIds?.length ? { complianceControlIds: dto.complianceControlIds } : {}),
      ...(dto.businessImpact ? { businessImpact: dto.businessImpact.trim() } : {}),
      ...(dto.effort ? { effort: dto.effort } : {}),
      ...(dto.remediationCli ? { remediationCli: dto.remediationCli } : {}),
    };

    const created = await this.prisma.$transaction(async (tx) => {
      const existing = await tx.finding.findUnique({
        where: { assetId_fingerprint: { assetId: asset.id, fingerprint } },
        select: { id: true },
      });

      const baseData = {
        category: dto.category,
        ruleId: normalizedRuleId,
        severity: dto.severity,
        cvssScore: new Prisma.Decimal(cvss),
        status: FindingStatus.OPEN,
        title: dto.title.trim().slice(0, 200),
        description: dto.description.trim(),
        recommendation: dto.recommendation.trim(),
        location: dto.location.trim().slice(0, 500),
        evidence: evidencePayload as Prisma.InputJsonValue,
        lastSeenAt: now,
        resolvedAt: null,
        dueDate,
        assignedToId: dto.assignedToId ?? null,
      };

      const saved = existing
        ? await tx.finding.update({
            where: { id: existing.id },
            data: baseData,
            select: findingSelect,
          })
        : await tx.finding.create({
            data: {
              ...baseData,
              organizationId: actor.organizationId,
              assetId: asset.id,
              fingerprint,
              firstSeenAt: now,
            },
            select: findingSelect,
          });

      await this.riskScores.snapshot(tx, {
        organizationId: actor.organizationId,
        assetId: asset.id,
        trigger: RiskScoreTrigger.FINDING_REVIEWED,
      });

      return saved;
    });

    this.audit.record({
      organizationId: actor.organizationId,
      action: 'finding.create_manual',
      actor,
      target: { type: 'finding', id: created.id, label: `${created.ruleId} · ${created.location}` },
      detail: {
        assetId: asset.id,
        severity: created.severity,
        category: created.category,
        complianceControlIds: dto.complianceControlIds ?? [],
      },
    });

    return this.enrichFinding(created);
  }

  /**
   * Triaje y gobierno por lotes (Bulk Operations) sobre múltiples hallazgos.
   */
  async bulkReview(actor: AuthUser, dto: BulkReviewFindingsDto) {
    const existingFindings = await this.prisma.finding.findMany({
      where: {
        id: { in: dto.findingIds },
        organizationId: actor.organizationId,
      },
      select: { id: true, assetId: true, status: true, ruleId: true },
    });

    if (existingFindings.length === 0) {
      throw new NotFoundException('Ninguno de los hallazgos seleccionados pertenece a la organización');
    }

    if (dto.assignedToId) {
      const assignedUser = await this.prisma.user.findFirst({
        where: { id: dto.assignedToId, organizationId: actor.organizationId },
        select: { id: true },
      });
      if (!assignedUser) {
        throw new BadRequestException('El usuario asignado no pertenece a la organización');
      }
    }

    const now = new Date();
    const validIds = existingFindings.map((f) => f.id);
    const affectedAssetIds = new Set<string>();

    if (dto.status !== undefined) {
      for (const f of existingFindings) {
        if (f.status !== dto.status) {
          affectedAssetIds.add(f.assetId);
        }
      }
    }

    const updatedItems = await this.prisma.$transaction(async (tx) => {
      const data: Prisma.FindingUncheckedUpdateManyInput = {};

      if (dto.status !== undefined) {
        data.status = dto.status;
        data.resolvedAt = (dto.status as FindingStatus) === FindingStatus.RESOLVED ? now : null;
        data.reviewedById = actor.id;
      }

      if (dto.note !== undefined) {
        data.reviewNote = dto.note ? dto.note.trim() : null;
        data.reviewedById = actor.id;
      }

      if (dto.assignedToId !== undefined) {
        data.assignedToId = dto.assignedToId ? dto.assignedToId : null;
      }

      if (dto.dueDate !== undefined) {
        data.dueDate = dto.dueDate ? new Date(dto.dueDate) : null;
      }

      if (dto.remediationNote !== undefined) {
        data.remediationNote = dto.remediationNote ? dto.remediationNote.trim() : null;
      }

      await tx.finding.updateMany({
        where: { id: { in: validIds }, organizationId: actor.organizationId },
        data,
      });

      for (const assetId of affectedAssetIds) {
        await this.riskScores.snapshot(tx, {
          organizationId: actor.organizationId,
          assetId,
          trigger: RiskScoreTrigger.FINDING_REVIEWED,
        });
      }

      return tx.finding.findMany({
        where: { id: { in: validIds }, organizationId: actor.organizationId },
        select: findingSelect,
      });
    });

    this.audit.record({
      organizationId: actor.organizationId,
      action: 'finding.bulk_review',
      actor,
      target: { type: 'finding_batch', id: validIds[0], label: `${validIds.length} hallazgos actualizados` },
      detail: {
        updatedCount: validIds.length,
        findingIds: validIds,
        ...(dto.status ? { status: dto.status } : {}),
        ...(dto.assignedToId !== undefined ? { assignedToId: dto.assignedToId } : {}),
        ...(dto.dueDate !== undefined ? { dueDate: dto.dueDate } : {}),
      },
    });

    return {
      updatedCount: validIds.length,
      affectedAssetsCount: affectedAssetIds.size,
      items: updatedItems.map((f) => this.enrichFinding(f)),
    };
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

    return this.enrichFinding(reviewed);
  }

  /**
   * Ejecuta una sonda puntual y rápida sobre la regla y ubicación del hallazgo.
   */
  async probeFinding(
    finding: FindingRow,
  ): Promise<{ stillReproducible: boolean; details?: Record<string, unknown> }> {
    const { category, ruleId, location, asset } = finding;
    const allowPrivate = this.allowPrivate;

    switch (category) {
      case FindingCategory.HTTP_HEADERS: {
        const timeoutMs = this.config?.get<number>('WEB_REQUEST_TIMEOUT_MS') ?? 5000;
        let targetUrl = location;
        if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
          targetUrl = `https://${asset.value}`;
        }
        let outcome: HttpProbeOutcome;
        try {
          outcome = await httpProbe(targetUrl, {
            allowPrivate,
            timeoutMs,
            signal: AbortSignal.timeout(timeoutMs),
            maxBodyBytes: 4096,
          });
        } catch (err) {
          return { stillReproducible: false, details: { error: (err as Error).message } };
        }

        if (!outcome.ok) {
          return { stillReproducible: false, details: { unreachable: true, error: outcome.error } };
        }

        const drafts = analyzeHeaders({
          finalUrl: outcome.finalUrl,
          status: outcome.status,
          headers: outcome.headers,
          httpsAvailable: new URL(outcome.finalUrl).protocol === 'https:',
        });

        const stillReproducible = drafts.some((d) => d.ruleId === ruleId);
        return {
          stillReproducible,
          details: {
            status: outcome.status,
            finalUrl: outcome.finalUrl,
            headersDetected: Object.keys(outcome.headers).length,
            remainingRules: drafts.map((d) => d.ruleId),
          },
        };
      }

      case FindingCategory.SENSITIVE_PATH: {
        const timeoutMs = this.config?.get<number>('WEB_REQUEST_TIMEOUT_MS') ?? 5000;
        let targetUrl = location;
        if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
          targetUrl = `https://${asset.value}${location.startsWith('/') ? '' : '/'}${location}`;
        }

        let outcome: HttpProbeOutcome;
        try {
          outcome = await httpProbe(targetUrl, {
            allowPrivate,
            timeoutMs,
            signal: AbortSignal.timeout(timeoutMs),
            maxBodyBytes: 64 * 1024,
            maxRedirects: 2,
          });
        } catch (err) {
          return { stillReproducible: false, details: { error: (err as Error).message } };
        }

        if (!outcome.ok) {
          return { stillReproducible: false, details: { unreachable: true, error: outcome.error } };
        }

        if (outcome.status === 404 || outcome.status === 403) {
          return { stillReproducible: false, details: { status: outcome.status } };
        }

        const rule = SENSITIVE_PATHS.find((r) => r.ruleId === ruleId);
        const candidate = (outcome.status >= 200 && outcome.status < 300) || outcome.status === 401;
        const matched = candidate && (rule ? rule.signature({
          status: outcome.status,
          contentType: outcome.contentType,
          body: outcome.body,
          text: outcome.body.toString('utf8'),
        }) : outcome.status === 200);

        return {
          stillReproducible: matched,
          details: { status: outcome.status, matched },
        };
      }

      case FindingCategory.TLS_CERTIFICATE: {
        let hostname = asset.value;
        let port = 443;
        try {
          if (location.startsWith('tls://') || location.startsWith('https://') || location.startsWith('http://')) {
            const u = new URL(location.replace(/^tls:/, 'https:'));
            hostname = u.hostname || hostname;
            if (u.port) port = Number(u.port);
          } else {
            const match = location.match(/(?:tls:\/\/)?([^:/]+)(?::(\d+))?/);
            if (match) {
              hostname = match[1] || hostname;
              if (match[2]) port = Number(match[2]);
            }
          }
        } catch {
          // fallback
        }

        let address: string;
        try {
          const target = await resolveScanTarget(hostname, isIP(hostname) ? AssetType.IP : AssetType.DOMAIN, allowPrivate);
          address = target.address;
        } catch (err) {
          throw new BadRequestException(`No se pudo resolver el host ${hostname}: ${(err as Error).message}`);
        }

        const probeOutcome = await tlsProbe({
          address,
          port,
          hostname,
          timeoutMs: 5000,
          signal: AbortSignal.timeout(5000),
          checkLegacy: ruleId === 'TLS-LEGACY-PROTOCOL',
        });

        if (!probeOutcome.ok) {
          if (probeOutcome.connectionRefused) {
            return { stillReproducible: false, details: { connectionRefused: true } };
          }
          return { stillReproducible: true, details: { error: probeOutcome.error } };
        }

        const drafts = analyzeTls(probeOutcome.info);
        const stillReproducible = drafts.some((d) => d.ruleId === ruleId);
        return {
          stillReproducible,
          details: {
            authorized: probeOutcome.info.authorized,
            protocol: probeOutcome.info.protocol,
            remainingRules: drafts.map((d) => d.ruleId),
          },
        };
      }

      case FindingCategory.EXPOSED_SERVICE: {
        let port = 0;
        if (finding.evidence && typeof finding.evidence === 'object' && 'port' in finding.evidence) {
          port = Number((finding.evidence as { port?: unknown }).port);
        }
        if (!port) {
          const m = location.match(/\d+/);
          port = m ? Number(m[0]) : 0;
        }
        if (!port) {
          return { stillReproducible: false, details: { error: 'No se pudo determinar el puerto' } };
        }

        let address: string;
        try {
          const target = await resolveScanTarget(asset.value, asset.type, allowPrivate);
          address = target.address;
        } catch (err) {
          throw new BadRequestException(`No se pudo resolver el activo ${asset.value}: ${(err as Error).message}`);
        }

        const isOpen = await tcpPortOpen(address, port, 3000);
        return {
          stillReproducible: isOpen,
          details: { port, open: isOpen },
        };
      }

      case FindingCategory.EMAIL_SECURITY: {
        const dns = createDnsClient(4000);
        try {
          const res = await analyzeEmailSecurity(asset.value, dns);
          const stillReproducible = res.findings.some((d) => d.ruleId === ruleId);
          return {
            stillReproducible,
            details: { remainingRules: res.findings.map((d) => d.ruleId) },
          };
        } catch (err) {
          return { stillReproducible: true, details: { error: (err as Error).message } };
        }
      }

      case FindingCategory.VULNERABLE_SOFTWARE: {
        let port = 0;
        if (finding.evidence && typeof finding.evidence === 'object' && 'port' in finding.evidence) {
          port = Number((finding.evidence as { port?: unknown }).port);
        }
        if (port > 0) {
          try {
            const target = await resolveScanTarget(asset.value, asset.type, allowPrivate);
            const isOpen = await tcpPortOpen(target.address, port, 3000);
            if (!isOpen) {
              return { stillReproducible: false, details: { port, open: false, portClosed: true } };
            }
          } catch {
            // continue
          }
        }
        return {
          stillReproducible: true,
          details: { note: 'El puerto asociado continúa respondiendo; se requiere escaneo de vulnerabilidades completo' },
        };
      }

      default:
        return {
          stillReproducible: true,
          details: { note: 'Categoría sin sonda directa puntual; se requiere escaneo completo' },
        };
    }
  }

  /**
   * Re-test puntual de un hallazgo (Sprint 7): sonda directa de 2-5s sobre la regla y ubicación.
   * Si la falla ya no se reproduce, marca RESOLVED, actualiza resolvedAt y recalcula el Security Score.
   * Si sigue presente, actualiza lastSeenAt (y si estaba RESOLVED, lo reabre a OPEN).
   */
  async retest(actor: AuthUser, id: string): Promise<RetestFindingResult> {
    const existing = await this.findOne(actor.organizationId, id);
    const probe = await this.probeFinding(existing);
    const { stillReproducible, details } = probe;
    const now = new Date();

    const updatedFinding = await this.prisma.$transaction(async (tx) => {
      let data: Prisma.FindingUpdateInput;

      if (!stillReproducible) {
        data = {
          status: FindingStatus.RESOLVED,
          resolvedAt: now,
          lastSeenAt: now,
        };
      } else {
        data = {
          lastSeenAt: now,
          ...(existing.status === FindingStatus.RESOLVED ? { status: FindingStatus.OPEN, resolvedAt: null } : {}),
        };
      }

      const updated = await tx.finding.update({
        where: { id },
        data,
        select: findingSelect,
      });

      if (existing.status !== updated.status) {
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
      target: { type: 'finding', id: updatedFinding.id, label: `${updatedFinding.ruleId} · ${updatedFinding.location}` },
      detail: {
        retest: true,
        stillReproducible,
        previousStatus: existing.status,
        newStatus: updatedFinding.status,
        ruleId: existing.ruleId,
        location: existing.location,
        details,
      },
    });

    return {
      finding: updatedFinding,
      stillReproducible,
      message: stillReproducible
        ? 'La vulnerabilidad o fallo de configuración sigue presente.'
        : '¡Verificación exitosa! El fallo ya no se reproduce y el hallazgo ha sido marcado como RESUELTO.',
      testedAt: now.toISOString(),
      details,
    };
  }

  /** Conteo de hallazgos abiertos por severidad y categoría (base del Security Score). */
  async summary(organizationId: string, assetId?: string) {
    const where: Prisma.FindingWhereInput = {
      organizationId,
      assetId,
      status: { in: [FindingStatus.OPEN, FindingStatus.IN_PROGRESS, FindingStatus.VERIFYING] },
    };
    const now = new Date();
    const in48h = new Date(now.getTime() + 48 * 60 * 60 * 1000);

    const [
      bySeverityRows,
      byCategoryRows,
      total,
      overdueCount,
      approachingCount,
      onTrackCount,
      noSlaCount,
      unassignedCount,
      assignedCount,
    ] = await Promise.all([
      this.prisma.finding.groupBy({ by: ['severity'], where, _count: { id: true } }),
      this.prisma.finding.groupBy({ by: ['category'], where, _count: { id: true } }),
      this.prisma.finding.count({ where }),
      this.prisma.finding.count({ where: { ...where, dueDate: { lt: now } } }),
      this.prisma.finding.count({ where: { ...where, dueDate: { gte: now, lte: in48h } } }),
      this.prisma.finding.count({ where: { ...where, dueDate: { gt: in48h } } }),
      this.prisma.finding.count({ where: { ...where, dueDate: null } }),
      this.prisma.finding.count({ where: { ...where, assignedToId: null } }),
      this.prisma.finding.count({ where: { ...where, assignedToId: { not: null } } }),
    ]);
    const bySeverity = emptyCounts();
    for (const row of bySeverityRows) bySeverity[row.severity] = row._count.id;
    const byCategory: Record<string, number> = {};
    for (const row of byCategoryRows) byCategory[row.category] = row._count.id;

    const bySource: Record<FindingSourceType, number> = {
      PERIMETER_SCAN: 0,
      CLOUD_CSPM: 0,
      THREAT_MALWARE_LAB: 0,
      MANUAL_AUDIT: 0,
    };
    const byFramework: Record<ComplianceFramework, number> = {
      ISO_27001: 0,
      PCI_DSS: 0,
      NIST_CSF: 0,
      CIS_CONTROLS: 0,
      SOC_2: 0,
    };

    const activeSample =
      (await this.prisma.finding.findMany?.({
        where,
        select: { ruleId: true, category: true, cloudAccountId: true, evidence: true },
      })) ?? [];

    if (activeSample.length > 0) {
      for (const row of activeSample) {
        const src = resolveFindingSource(row);
        bySource[src] = (bySource[src] ?? 0) + 1;
        const controls = resolveComplianceControls(row.ruleId, row.evidence);
        const frameworksTouched = new Set<ComplianceFramework>(controls.map((c) => c.framework));
        for (const fw of frameworksTouched) {
          byFramework[fw] = (byFramework[fw] ?? 0) + 1;
        }
      }
    } else {
      for (const row of byCategoryRows) {
        if ((CLOUD_FINDING_CATEGORIES as string[]).includes(row.category)) {
          bySource.CLOUD_CSPM += row._count.id;
        } else {
          bySource.PERIMETER_SCAN += row._count.id;
        }
      }
    }

    return {
      total,
      bySeverity,
      byCategory,
      bySource,
      byFramework,
      severityOrder: SEVERITY_ORDER,
      sla: {
        overdue: overdueCount,
        approaching: approachingCount,
        onTrack: onTrackCount,
        noSla: noSlaCount,
        unassigned: unassignedCount,
        assigned: assignedCount,
      },
    };
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
      cloudAccountId: query.cloudAccountId,
      severity: query.severity,
      status: query.status,
      category: query.category,
      ...(from || to
        ? {
            firstSeenAt: {
              ...(from ? { gte: new Date(from) } : {}),
              ...(to ? { lte: new Date(to) } : {}),
            },
          }
        : {}),
    };

    this.applyAdvancedWhere(where, query);

    if (query.assignedToId) {
      if (query.assignedToId === 'unassigned') {
        where.assignedToId = null;
      } else {
        where.assignedToId = query.assignedToId;
      }
    }

    if (query.slaStatus) {
      const now = new Date();
      const in48h = new Date(now.getTime() + 48 * 60 * 60 * 1000);
      const openStatuses: FindingStatus[] = [
        FindingStatus.OPEN,
        FindingStatus.IN_PROGRESS,
        FindingStatus.VERIFYING,
      ];

      if (query.slaStatus === 'OVERDUE') {
        where.status = query.status ?? { in: openStatuses };
        where.dueDate = { lt: now };
      } else if (query.slaStatus === 'APPROACHING') {
        where.status = query.status ?? { in: openStatuses };
        where.dueDate = { gte: now, lte: in48h };
      } else if (query.slaStatus === 'ON_TRACK') {
        where.status = query.status ?? { in: openStatuses };
        where.dueDate = { gt: in48h };
      } else if (query.slaStatus === 'NO_SLA') {
        where.status = query.status ?? { in: openStatuses };
        where.dueDate = null;
      }
    }

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
        'sla_status',
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
          const sla = computeSla(finding.dueDate, finding.status);
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
            sla.status,
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
