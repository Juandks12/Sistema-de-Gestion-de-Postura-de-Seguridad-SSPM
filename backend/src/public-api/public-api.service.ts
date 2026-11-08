import { Injectable, Optional } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { ComplianceService } from '../compliance/compliance.service';
import { AttackPathsService } from '../findings/attack-paths.service';
import { PrismaService } from '../prisma/prisma.service';
import { RiskScoresService } from '../risk/risk-scores.service';
import {
  PublicAlertsQueryDto,
  PublicAssetsQueryDto,
  PublicAttackPathsQueryDto,
  PublicComplianceQueryDto,
  PublicFindingsQueryDto,
  PublicThreatLabQueryDto,
} from './dto/public-query.dto';

const publicFindingSelect = {
  id: true,
  ruleId: true,
  category: true,
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
  dueDate: true,
  createdAt: true,
  updatedAt: true,
  asset: {
    select: {
      id: true,
      type: true,
      value: true,
      name: true,
      criticality: true,
    },
  },
} satisfies Prisma.FindingSelect;

const publicAlertSelect = {
  id: true,
  type: true,
  severity: true,
  title: true,
  message: true,
  data: true,
  acknowledgedAt: true,
  createdAt: true,
  asset: {
    select: {
      id: true,
      type: true,
      value: true,
      name: true,
    },
  },
} satisfies Prisma.AlertSelect;

@Injectable()
export class PublicApiService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly riskScoresService: RiskScoresService,
    @Optional() private readonly attackPathsService?: AttackPathsService,
    @Optional() private readonly complianceService?: ComplianceService,
  ) {}

  /** Obtiene hallazgos con soporte de cursor temporal para sincronización incremental */
  async getFindings(organizationId: string, query: PublicFindingsQueryDto) {
    const where: Prisma.FindingWhereInput = {
      organizationId,
      ...(query.since ? { updatedAt: { gte: new Date(query.since) } } : {}),
      ...(query.status ? { status: query.status } : {}),
      ...(query.severity ? { severity: query.severity } : {}),
      ...(query.assetId ? { assetId: query.assetId } : {}),
    };

    const items = await this.prisma.finding.findMany({
      where,
      select: publicFindingSelect,
      orderBy: { updatedAt: 'asc' },
      take: query.limit,
    });

    return {
      total: items.length,
      since: query.since ?? null,
      items,
    };
  }

  /** Obtiene alertas de seguridad con cursor incremental */
  async getAlerts(organizationId: string, query: PublicAlertsQueryDto) {
    const where: Prisma.AlertWhereInput = {
      organizationId,
      ...(query.since ? { createdAt: { gte: new Date(query.since) } } : {}),
      ...(query.severity ? { severity: query.severity } : {}),
    };

    const items = await this.prisma.alert.findMany({
      where,
      select: publicAlertSelect,
      orderBy: { createdAt: 'asc' },
      take: query.limit,
    });

    return {
      total: items.length,
      since: query.since ?? null,
      items,
    };
  }

  /** Obtiene la postura de seguridad y métricas globales de la organización */
  async getPosture(organizationId: string) {
    const [snapshot, totalAssets] = await Promise.all([
      this.riskScoresService.latest(organizationId),
      this.prisma.asset.count({ where: { organizationId, isActive: true } }),
    ]);

    return {
      organizationId,
      score: snapshot?.score ?? null,
      grade: snapshot?.grade ?? null,
      computedAt: snapshot?.computedAt ?? null,
      trigger: snapshot?.trigger ?? null,
      totalAssets,
      scoredAssets: snapshot?.scoredAssets ?? 0,
      findingsSummary: {
        critical: snapshot?.criticalCount ?? 0,
        high: snapshot?.highCount ?? 0,
        medium: snapshot?.mediumCount ?? 0,
        low: snapshot?.lowCount ?? 0,
        info: snapshot?.infoCount ?? 0,
      },
      breakdown: snapshot?.breakdown ?? null,
    };
  }

  /** Obtiene el inventario de activos con criticidad y resumen de hallazgos abiertos */
  async getAssets(organizationId: string, query: PublicAssetsQueryDto) {
    const assets = await this.prisma.asset.findMany({
      where: { organizationId, isActive: true },
      select: {
        id: true,
        type: true,
        value: true,
        name: true,
        criticality: true,
        tags: true,
        verifiedAt: true,
        verificationMethod: true,
        lastScannedAt: true,
        createdAt: true,
        updatedAt: true,
        findings: {
          where: {
            status: { in: ['OPEN', 'IN_PROGRESS', 'VERIFYING'] },
          },
          select: {
            severity: true,
          },
        },
      },
      orderBy: { createdAt: 'asc' },
      take: query.limit,
    });

    const items = assets.map((a) => {
      const openFindings = {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
        total: a.findings.length,
      };
      for (const f of a.findings) {
        if (f.severity === 'CRITICAL') openFindings.critical++;
        else if (f.severity === 'HIGH') openFindings.high++;
        else if (f.severity === 'MEDIUM') openFindings.medium++;
        else if (f.severity === 'LOW') openFindings.low++;
        else if (f.severity === 'INFO') openFindings.info++;
      }

      return {
        id: a.id,
        type: a.type,
        value: a.value,
        name: a.name,
        criticality: a.criticality,
        tags: a.tags,
        isVerified: !!a.verifiedAt,
        verifiedAt: a.verifiedAt,
        verificationMethod: a.verificationMethod,
        lastScannedAt: a.lastScannedAt,
        createdAt: a.createdAt,
        updatedAt: a.updatedAt,
        openFindings,
      };
    });

    return {
      total: items.length,
      items,
    };
  }

  /** Exporta rutas de ataque correlacionadas (Kill-Chains) para SIEM/SOAR */
  async getAttackPaths(organizationId: string, query: PublicAttackPathsQueryDto) {
    const items = this.attackPathsService
      ? await this.attackPathsService.analyzeAttackPaths(organizationId, query.assetId)
      : [];
    return {
      organizationId,
      total: items.length,
      assetId: query.assetId ?? null,
      items,
    };
  }

  /** Exporta matriz de cumplimiento normativo GRC (ISO 27001, PCI-DSS, NIST CSF, CIS Controls, SOC 2) */
  async getCompliance(organizationId: string, query: PublicComplianceQueryDto) {
    if (!this.complianceService) {
      return { organizationId, overview: null, frameworkDetails: null };
    }
    const overview = await this.complianceService.getOverview(organizationId);
    const frameworkDetails = query.framework
      ? await this.complianceService.getFrameworkDetails(organizationId, query.framework)
      : null;

    return {
      organizationId,
      overview,
      frameworkDetails,
    };
  }

  /** Exporta análisis forenses del Laboratorio de Malware y Phishing (IoCs, hashes SHA-256, veredictos) */
  async getThreatLab(organizationId: string, query: PublicThreatLabQueryDto) {
    const where: Prisma.MalwareAnalysisWhereInput = {
      organizationId,
      ...(query.since ? { createdAt: { gte: new Date(query.since) } } : {}),
      ...(query.artifactType ? { artifactType: query.artifactType } : {}),
      ...(query.verdict ? { verdict: query.verdict } : {}),
    };

    const items = await this.prisma.malwareAnalysis.findMany({
      where,
      select: {
        id: true,
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
        indicators: true,
        threatIntel: true,
        promotedFindingId: true,
        createdAt: true,
        asset: { select: { id: true, type: true, value: true, name: true } },
      },
      orderBy: { createdAt: 'desc' },
      take: query.limit,
    });

    return {
      total: items.length,
      since: query.since ?? null,
      items,
    };
  }
}
