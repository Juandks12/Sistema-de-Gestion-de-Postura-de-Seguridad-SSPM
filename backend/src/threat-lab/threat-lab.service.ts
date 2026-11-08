import { BadRequestException, Injectable, NotFoundException } from '@nestjs/common';
import {
  FindingCategory,
  FindingSeverity,
  FindingStatus,
  MalwareArtifactType,
  MalwareVerdict,
  Prisma,
  RiskScoreTrigger,
} from '@prisma/client';
import { AuditService } from '../audit/audit.service';
import { AuthUser } from '../common/interfaces/auth-user.interface';
import { FindingsService, fingerprintOf } from '../findings/findings.service';
import { computeDefaultFindingDueDate } from '../findings/grc-taxonomy.catalog';
import { getRule } from '../findings/rules.catalog';
import { PrismaService } from '../prisma/prisma.service';
import { RiskScoresService } from '../risk/risk-scores.service';
import { analyzeEmailArtifact } from './analyzers/email-malware.analyzer';
import { analyzeFileArtifact } from './analyzers/file-malware.analyzer';
import { analyzeUrlArtifact } from './analyzers/url-malware.analyzer';
import {
  AnalyzeEmailDto,
  AnalyzeFileDto,
  AnalyzeUrlDto,
  ListMalwareAnalysesQuery,
  PromoteAnalysisToFindingDto,
} from './dto/threat-lab.dto';

const analysisSelect = {
  id: true,
  organizationId: true,
  assetId: true,
  requestedById: true,
  artifactType: true,
  artifactName: true,
  mimeType: true,
  sizeBytes: true,
  sha256: true,
  sha1: true,
  md5: true,
  verdict: true,
  riskScore: true,
  severity: true,
  summary: true,
  staticAnalysis: true,
  threatIntel: true,
  indicators: true,
  recommendations: true,
  promotedFindingId: true,
  createdAt: true,
  asset: { select: { id: true, name: true, value: true, type: true } },
  requestedBy: { select: { id: true, fullName: true, email: true } },
} satisfies Prisma.MalwareAnalysisSelect;

@Injectable()
export class ThreatLabService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly findings: FindingsService,
    private readonly riskScores: RiskScoresService,
    private readonly audit: AuditService,
  ) {}

  private async verifyAssetIfPresent(organizationId: string, assetId?: string): Promise<void> {
    if (!assetId) return;
    const asset = await this.prisma.asset.findFirst({
      where: { id: assetId, organizationId },
      select: { id: true },
    });
    if (!asset) {
      throw new NotFoundException('El activo asociado no pertenece a la organización');
    }
  }

  async analyzeEmail(actor: AuthUser, dto: AnalyzeEmailDto) {
    await this.verifyAssetIfPresent(actor.organizationId, dto.assetId);
    const analysis = analyzeEmailArtifact({
      rawContent: dto.rawContent,
      artifactName: dto.artifactName,
    });

    const saved = await this.prisma.malwareAnalysis.create({
      data: {
        organizationId: actor.organizationId,
        assetId: dto.assetId ?? null,
        requestedById: actor.id,
        artifactType: MalwareArtifactType.EMAIL,
        artifactName: analysis.artifactName.slice(0, 500),
        mimeType: 'message/rfc822',
        sizeBytes: analysis.sizeBytes,
        sha256: analysis.sha256,
        sha1: analysis.sha1,
        md5: analysis.md5,
        verdict: analysis.verdict,
        riskScore: analysis.riskScore,
        severity: analysis.severity,
        summary: analysis.summary,
        staticAnalysis: analysis.staticAnalysis as unknown as Prisma.InputJsonValue,
        threatIntel: analysis.threatIntel as unknown as Prisma.InputJsonValue,
        indicators: analysis.indicators as unknown as Prisma.InputJsonValue,
        recommendations: analysis.recommendations as unknown as Prisma.InputJsonValue,
      },
      select: analysisSelect,
    });

    this.audit.record({
      organizationId: actor.organizationId,
      action: 'threat_lab.analyze',
      actor,
      target: { type: 'malware_analysis', id: saved.id, label: `EMAIL · ${saved.artifactName}` },
      detail: {
        artifactType: 'EMAIL',
        verdict: saved.verdict,
        riskScore: saved.riskScore,
        sha256: saved.sha256,
      },
    });

    return saved;
  }

  async analyzeFile(actor: AuthUser, dto: AnalyzeFileDto) {
    await this.verifyAssetIfPresent(actor.organizationId, dto.assetId);
    if (!dto.contentBase64 && !dto.rawText && !dto.sha256) {
      throw new BadRequestException(
        'Debe proporcionar el contenido del archivo (contentBase64 / rawText) o su hash SHA-256.',
      );
    }

    const analysis = await analyzeFileArtifact({
      fileName: dto.fileName,
      mimeType: dto.mimeType,
      contentBase64: dto.contentBase64,
      rawText: dto.rawText,
      sha256: dto.sha256,
    });

    const saved = await this.prisma.malwareAnalysis.create({
      data: {
        organizationId: actor.organizationId,
        assetId: dto.assetId ?? null,
        requestedById: actor.id,
        artifactType: MalwareArtifactType.FILE,
        artifactName: analysis.artifactName.slice(0, 500),
        mimeType: analysis.mimeType.slice(0, 120),
        sizeBytes: analysis.sizeBytes,
        sha256: analysis.sha256,
        sha1: analysis.sha1,
        md5: analysis.md5,
        verdict: analysis.verdict,
        riskScore: analysis.riskScore,
        severity: analysis.severity,
        summary: analysis.summary,
        staticAnalysis: analysis.staticAnalysis as unknown as Prisma.InputJsonValue,
        threatIntel: analysis.threatIntel as unknown as Prisma.InputJsonValue,
        indicators: analysis.indicators as unknown as Prisma.InputJsonValue,
        recommendations: analysis.recommendations as unknown as Prisma.InputJsonValue,
      },
      select: analysisSelect,
    });

    this.audit.record({
      organizationId: actor.organizationId,
      action: 'threat_lab.analyze',
      actor,
      target: { type: 'malware_analysis', id: saved.id, label: `FILE · ${saved.artifactName}` },
      detail: {
        artifactType: 'FILE',
        verdict: saved.verdict,
        riskScore: saved.riskScore,
        sha256: saved.sha256,
      },
    });

    return saved;
  }

  async analyzeUrl(actor: AuthUser, dto: AnalyzeUrlDto) {
    await this.verifyAssetIfPresent(actor.organizationId, dto.assetId);
    const analysis = analyzeUrlArtifact({ url: dto.url });

    const saved = await this.prisma.malwareAnalysis.create({
      data: {
        organizationId: actor.organizationId,
        assetId: dto.assetId ?? null,
        requestedById: actor.id,
        artifactType: MalwareArtifactType.URL,
        artifactName: analysis.artifactName.slice(0, 500),
        mimeType: 'text/uri-list',
        sizeBytes: Buffer.byteLength(dto.url, 'utf8'),
        sha256: analysis.sha256,
        sha1: analysis.sha1,
        md5: analysis.md5,
        verdict: analysis.verdict,
        riskScore: analysis.riskScore,
        severity: analysis.severity,
        summary: analysis.summary,
        staticAnalysis: analysis.staticAnalysis as unknown as Prisma.InputJsonValue,
        threatIntel: analysis.threatIntel as unknown as Prisma.InputJsonValue,
        indicators: analysis.indicators as unknown as Prisma.InputJsonValue,
        recommendations: analysis.recommendations as unknown as Prisma.InputJsonValue,
      },
      select: analysisSelect,
    });

    this.audit.record({
      organizationId: actor.organizationId,
      action: 'threat_lab.analyze',
      actor,
      target: { type: 'malware_analysis', id: saved.id, label: `URL · ${saved.artifactName}` },
      detail: {
        artifactType: 'URL',
        verdict: saved.verdict,
        riskScore: saved.riskScore,
        sha256: saved.sha256,
      },
    });

    return saved;
  }

  async summary(organizationId: string) {
    const [total, byTypeRows, byVerdictRows, promotedCount] = await Promise.all([
      this.prisma.malwareAnalysis.count({ where: { organizationId } }),
      this.prisma.malwareAnalysis.groupBy({
        by: ['artifactType'],
        where: { organizationId },
        _count: { id: true },
      }),
      this.prisma.malwareAnalysis.groupBy({
        by: ['verdict'],
        where: { organizationId },
        _count: { id: true },
      }),
      this.prisma.malwareAnalysis.count({
        where: { organizationId, promotedFindingId: { not: null } },
      }),
    ]);

    const byType: Record<MalwareArtifactType, number> = {
      EMAIL: 0,
      FILE: 0,
      URL: 0,
    };
    for (const row of byTypeRows) {
      byType[row.artifactType] = row._count.id;
    }

    const byVerdict: Record<MalwareVerdict, number> = {
      CLEAN: 0,
      SUSPICIOUS: 0,
      MALICIOUS: 0,
    };
    for (const row of byVerdictRows) {
      byVerdict[row.verdict] = row._count.id;
    }

    return {
      total,
      byType,
      byVerdict,
      promotedCount,
    };
  }

  async findAll(organizationId: string, query: ListMalwareAnalysesQuery) {
    const where: Prisma.MalwareAnalysisWhereInput = {
      organizationId,
      artifactType: query.artifactType,
      verdict: query.verdict,
      assetId: query.assetId,
    };

    if (query.search && query.search.trim().length > 0) {
      const q = query.search.trim();
      where.OR = [
        { artifactName: { contains: q, mode: 'insensitive' } },
        { sha256: { contains: q, mode: 'insensitive' } },
        { summary: { contains: q, mode: 'insensitive' } },
      ];
    }

    const [items, total] = await this.prisma.$transaction([
      this.prisma.malwareAnalysis.findMany({
        where,
        select: analysisSelect,
        orderBy: { createdAt: 'desc' },
        skip: (query.page - 1) * query.pageSize,
        take: query.pageSize,
      }),
      this.prisma.malwareAnalysis.count({ where }),
    ]);

    return {
      items,
      meta: {
        total,
        page: query.page,
        pageSize: query.pageSize,
        totalPages: Math.max(1, Math.ceil(total / query.pageSize)),
      },
    };
  }

  async findOne(organizationId: string, id: string) {
    const item = await this.prisma.malwareAnalysis.findFirst({
      where: { id, organizationId },
      select: analysisSelect,
    });
    if (!item) {
      throw new NotFoundException('Análisis forense no encontrado');
    }
    return item;
  }

  /**
   * Promueve un análisis del Laboratorio de Malware y Phishing a un Hallazgo formal
   * en el Centro Maestro de Hallazgos y GRC, asociándolo a un activo y recalculando su Security Score.
   */
  async promoteToFinding(
    actor: AuthUser,
    id: string,
    dto: PromoteAnalysisToFindingDto,
  ) {
    const analysis = await this.findOne(actor.organizationId, id);
    const asset = await this.prisma.asset.findFirst({
      where: { id: dto.assetId, organizationId: actor.organizationId },
      select: { id: true, name: true, value: true },
    });
    if (!asset) {
      throw new NotFoundException('El activo seleccionado no pertenece a la organización');
    }

    if (dto.assignedToId) {
      const user = await this.prisma.user.findFirst({
        where: { id: dto.assignedToId, organizationId: actor.organizationId },
        select: { id: true },
      });
      if (!user) {
        throw new BadRequestException('El usuario asignado no pertenece a la organización');
      }
    }

    // Determine ruleId based on artifactType and staticAnalysis
    let ruleId = 'THREAT-FILE-MALICIOUS-HASH';
    if (analysis.artifactType === MalwareArtifactType.EMAIL) {
      ruleId = 'THREAT-EMAIL-PHISHING-BEC';
    } else if (analysis.artifactType === MalwareArtifactType.URL) {
      ruleId = 'THREAT-URL-MALICIOUS-PHISHING';
    } else {
      const st = (analysis.staticAnalysis ?? {}) as Record<string, unknown>;
      const hasMacros = Array.isArray(st.macroIndicators) && st.macroIndicators.length > 0;
      const hasPdfActions = Array.isArray(st.pdfDangerousActions) && st.pdfDangerousActions.length > 0;
      if (hasMacros || hasPdfActions) {
        ruleId = 'THREAT-FILE-SUSPICIOUS-MACRO-PDF';
      }
    }

    const rule = getRule(ruleId);
    const effectiveSeverity =
      analysis.severity === FindingSeverity.INFO
        ? FindingSeverity.MEDIUM
        : analysis.severity;
    const location =
      analysis.artifactType === MalwareArtifactType.URL
        ? analysis.artifactName.slice(0, 500)
        : `threat-lab://${analysis.artifactType.toLowerCase()}/${analysis.artifactName.slice(0, 120)} (sha256:${(analysis.sha256 ?? '').slice(0, 16)})`;

    const fingerprint = fingerprintOf(ruleId, location);
    const now = new Date();
    const dueDate = computeDefaultFindingDueDate(effectiveSeverity, now);

    const recommendationsList = Array.isArray(analysis.recommendations)
      ? (analysis.recommendations as string[])
      : [];
    const recommendationText =
      recommendationsList.length > 0
        ? recommendationsList.join(' ')
        : rule.recommendation;

    const evidencePayload: Record<string, unknown> = {
      sourceType: 'THREAT_MALWARE_LAB',
      malwareAnalysisId: analysis.id,
      artifactType: analysis.artifactType,
      artifactName: analysis.artifactName,
      verdict: analysis.verdict,
      riskScore: analysis.riskScore,
      sha256: analysis.sha256,
      md5: analysis.md5,
      sha1: analysis.sha1,
      indicators: analysis.indicators,
      threatIntel: analysis.threatIntel,
      complianceControlIds: ['ISO_27001:A.8.23', 'PCI_DSS:Req 2.2'],
    };

    const result = await this.prisma.$transaction(async (tx) => {
      const existing = await tx.finding.findUnique({
        where: { assetId_fingerprint: { assetId: asset.id, fingerprint } },
        select: { id: true },
      });

      const baseFindingData = {
        category: FindingCategory.MALWARE_THREAT,
        ruleId,
        severity: effectiveSeverity,
        cvssScore: new Prisma.Decimal(rule.cvss),
        status: FindingStatus.OPEN,
        title: (dto.customTitle?.trim() || `${rule.title}: ${analysis.artifactName}`).slice(0, 200),
        description: analysis.summary,
        recommendation: recommendationText,
        location,
        evidence: evidencePayload as Prisma.InputJsonValue,
        lastSeenAt: now,
        resolvedAt: null,
        dueDate,
        assignedToId: dto.assignedToId ?? null,
      };

      const finding = existing
        ? await tx.finding.update({
            where: { id: existing.id },
            data: baseFindingData,
          })
        : await tx.finding.create({
            data: {
              ...baseFindingData,
              organizationId: actor.organizationId,
              assetId: asset.id,
              fingerprint,
              firstSeenAt: now,
            },
          });

      const updatedAnalysis = await tx.malwareAnalysis.update({
        where: { id: analysis.id },
        data: {
          assetId: asset.id,
          promotedFindingId: finding.id,
        },
        select: analysisSelect,
      });

      await this.riskScores.snapshot(tx, {
        organizationId: actor.organizationId,
        assetId: asset.id,
        trigger: RiskScoreTrigger.FINDING_REVIEWED,
      });

      return { findingId: finding.id, updatedAnalysis };
    });

    this.audit.record({
      organizationId: actor.organizationId,
      action: 'threat_lab.promote_finding',
      actor,
      target: { type: 'finding', id: result.findingId, label: `${ruleId} · ${analysis.artifactName}` },
      detail: {
        analysisId: analysis.id,
        assetId: asset.id,
        artifactType: analysis.artifactType,
        verdict: analysis.verdict,
        riskScore: analysis.riskScore,
      },
    });

    const enrichedFinding = await this.findings.findOne(actor.organizationId, result.findingId);
    return {
      analysis: result.updatedAnalysis,
      finding: enrichedFinding,
    };
  }
}
