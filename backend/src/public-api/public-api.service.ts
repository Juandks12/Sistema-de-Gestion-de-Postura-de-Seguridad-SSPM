import { Injectable } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { PrismaService } from '../prisma/prisma.service';
import { RiskScoresService } from '../risk/risk-scores.service';
import { PublicAlertsQueryDto, PublicAssetsQueryDto, PublicFindingsQueryDto } from './dto/public-query.dto';

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
}
