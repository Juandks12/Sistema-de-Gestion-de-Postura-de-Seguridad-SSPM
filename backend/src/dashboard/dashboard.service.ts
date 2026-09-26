import { Injectable, NotFoundException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { FindingStatus, Prisma, RiskScoreScope, ScanStatus, ScanType } from '@prisma/client';
import { PrismaService } from '../prisma/prisma.service';
import { RiskScoresService } from '../risk/risk-scores.service';
import { emptyCounts, gradeFor, SEVERITY_ORDER } from '../risk/scoring';

const DAY_MS = 24 * 60 * 60 * 1000;

const topFindingSelect = {
  id: true,
  assetId: true,
  category: true,
  ruleId: true,
  severity: true,
  cvssScore: true,
  title: true,
  location: true,
  recommendation: true,
  firstSeenAt: true,
  lastSeenAt: true,
  asset: { select: { id: true, value: true, name: true, type: true } },
} satisfies Prisma.FindingSelect;

/**
 * Datos agregados para el dashboard (sección 8 del documento). Todas las
 * consultas se filtran por la organización del usuario autenticado.
 */
@Injectable()
export class DashboardService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly riskScores: RiskScoresService,
    private readonly config: ConfigService,
  ) {}

  /** 8.1 Vista general. */
  async overview(organizationId: string) {
    const now = new Date();
    const dayAgo = new Date(now.getTime() - DAY_MS);
    const weekAgo = new Date(now.getTime() - 7 * DAY_MS);

    const [current, latest, previous, weekBefore, assets, scans, findingsByStatus, byCategoryRows, topFindings, recentScans, running] =
      await Promise.all([
        this.riskScores.current(organizationId),
        this.riskScores.latest(organizationId),
        this.riskScores.latestBefore(organizationId, now).then((s) => (s ? this.riskScores.latestBefore(organizationId, s.computedAt) : null)),
        this.riskScores.latestBefore(organizationId, weekAgo),
        this.prisma.asset.groupBy({ by: ['isActive'], where: { organizationId }, _count: { id: true } }),
        this.prisma.scan.groupBy({ by: ['status'], where: { organizationId, createdAt: { gte: weekAgo } }, _count: { id: true } }),
        this.prisma.finding.groupBy({ by: ['status'], where: { organizationId }, _count: { id: true } }),
        this.prisma.finding.groupBy({ by: ['category'], where: { organizationId, status: FindingStatus.OPEN }, _count: { id: true } }),
        this.prisma.finding.findMany({
          where: { organizationId, status: FindingStatus.OPEN },
          orderBy: [{ cvssScore: 'desc' }, { lastSeenAt: 'desc' }],
          take: 10,
          select: topFindingSelect,
        }),
        this.prisma.scan.findMany({
          where: { organizationId },
          orderBy: { createdAt: 'desc' },
          take: 5,
          select: {
            id: true,
            type: true,
            status: true,
            createdAt: true,
            finishedAt: true,
            errorMessage: true,
            asset: { select: { id: true, value: true, name: true } },
          },
        }),
        this.prisma.scan.count({ where: { organizationId, status: { in: [ScanStatus.PENDING, ScanStatus.RUNNING] } } }),
      ]);

    const assetCounts = { total: 0, active: 0, inactive: 0 };
    for (const row of assets) {
      assetCounts.total += row._count.id;
      if (row.isActive) assetCounts.active += row._count.id;
      else assetCounts.inactive += row._count.id;
    }

    const scanStats: Record<string, number> = { PENDING: 0, RUNNING: 0, COMPLETED: 0, FAILED: 0, CANCELLED: 0 };
    for (const row of scans) scanStats[row.status] = row._count.id;
    const completedLastDay = await this.prisma.scan.count({
      where: { organizationId, status: ScanStatus.COMPLETED, finishedAt: { gte: dayAgo } },
    });

    const findingStatus: Record<string, number> = { OPEN: 0, RESOLVED: 0, ACCEPTED: 0, FALSE_POSITIVE: 0 };
    for (const row of findingsByStatus) findingStatus[row.status] = row._count.id;
    const byCategory: Record<string, number> = {};
    for (const row of byCategoryRows) byCategory[row.category] = row._count.id;

    const trend = (from: number | null | undefined) =>
      current.score === null || from === null || from === undefined ? null : current.score - from;

    const lastScanAt = await this.prisma.scan.findFirst({
      where: { organizationId, status: ScanStatus.COMPLETED },
      orderBy: { finishedAt: 'desc' },
      select: { finishedAt: true },
    });

    return {
      generatedAt: now,
      securityScore: {
        score: current.score,
        grade: current.grade,
        label: current.label,
        description: current.description,
        scoredAssets: current.scoredAssets,
        totalAssets: current.totalAssets,
        lastSnapshotAt: latest?.computedAt ?? null,
        trend: {
          sincePrevious: trend(previous?.score),
          sinceLastWeek: trend(weekBefore?.score),
          previousScore: previous?.score ?? null,
          lastWeekScore: weekBefore?.score ?? null,
        },
      },
      findings: {
        open: findingStatus.OPEN,
        bySeverity: current.counts,
        severityOrder: SEVERITY_ORDER,
        byCategory,
        byStatus: findingStatus,
      },
      assets: assetCounts,
      scans: {
        inProgress: running,
        completedLast24h: completedLastDay,
        last7Days: scanStats,
        lastCompletedAt: lastScanAt?.finishedAt ?? null,
      },
      topFindings,
      recentScans,
    };
  }

  /** 8.4 / 8.5 Tabla de activos con score, hallazgos y último escaneo. */
  async assets(organizationId: string) {
    const rows = await this.prisma.asset.findMany({
      where: { organizationId },
      orderBy: { createdAt: 'asc' },
      select: {
        id: true,
        type: true,
        value: true,
        name: true,
        isActive: true,
        verifiedAt: true,
        verificationMethod: true,
        lastScannedAt: true,
        findings: { where: { status: FindingStatus.OPEN }, select: { severity: true } },
        scans: {
          where: { status: ScanStatus.COMPLETED },
          orderBy: { finishedAt: 'desc' },
          select: { type: true, finishedAt: true },
        },
        _count: { select: { scans: true } },
      },
    });

    const states = await this.riskScores.computeAllAssets(this.prisma, organizationId);
    const byAsset = new Map(states.map((s) => [s.assetId, s]));

    const items = rows.map((a) => {
      const state = byAsset.get(a.id);
      const counts = emptyCounts();
      for (const f of a.findings) counts[f.severity] += 1;
      const lastByType: Partial<Record<ScanType, Date | null>> = {};
      for (const s of a.scans) if (!(s.type in lastByType)) lastByType[s.type] = s.finishedAt;
      const scored = state?.scored ?? a.scans.length > 0;
      const score = scored ? (state?.result.score ?? null) : null;
      return {
        id: a.id,
        type: a.type,
        value: a.value,
        name: a.name,
        isActive: a.isActive,
        verified: a.verifiedAt !== null,
        verificationMethod: a.verificationMethod,
        scored,
        score,
        grade: score === null ? null : gradeFor(score).grade,
        openFindings: a.findings.length,
        bySeverity: counts,
        lastScannedAt: a.lastScannedAt,
        lastScanByType: lastByType,
        totalScans: a._count.scans,
      };
    });

    // Los activos con peor postura primero; los no evaluados al final.
    items.sort((x, y) => {
      if (x.score === null && y.score === null) return 0;
      if (x.score === null) return 1;
      if (y.score === null) return -1;
      return x.score - y.score;
    });
    return {
      items,
      total: items.length,
      verificationRequired: this.config.get<boolean>('ASSET_VERIFICATION_REQUIRED') !== false,
    };
  }

  /** 8.4 Vista detallada por activo. */
  async asset(organizationId: string, assetId: string) {
    const asset = await this.prisma.asset.findFirst({
      where: { id: assetId, organizationId },
      select: {
        id: true,
        type: true,
        value: true,
        name: true,
        description: true,
        isActive: true,
        authorizationConfirmed: true,
        verifiedAt: true,
        verificationMethod: true,
        verificationScope: true,
        lastScannedAt: true,
        createdAt: true,
      },
    });
    if (!asset) throw new NotFoundException('Activo no encontrado');

    const [score, history, findings, lastPortScan, scansByType] = await Promise.all([
      this.riskScores.current(organizationId, assetId),
      this.riskScores.history(organizationId, { assetId, granularity: 'day' }),
      this.prisma.finding.findMany({
        where: { assetId, organizationId, status: FindingStatus.OPEN },
        orderBy: [{ cvssScore: 'desc' }, { lastSeenAt: 'desc' }],
        select: topFindingSelect,
      }),
      this.prisma.scan.findFirst({
        where: { assetId, type: ScanType.PORT_SCAN, status: ScanStatus.COMPLETED },
        orderBy: { finishedAt: 'desc' },
        select: {
          id: true,
          finishedAt: true,
          targetAddress: true,
          ports: {
            where: { state: 'open' },
            orderBy: { port: 'asc' },
            select: { port: true, protocol: true, serviceName: true, product: true, version: true, tunnel: true },
          },
        },
      }),
      this.prisma.scan.findMany({
        where: { assetId, organizationId },
        orderBy: { createdAt: 'desc' },
        distinct: ['type'],
        select: { id: true, type: true, status: true, createdAt: true, finishedAt: true, errorMessage: true },
      }),
    ]);

    const byCategory: Record<string, number> = {};
    for (const f of findings) byCategory[f.category] = (byCategory[f.category] ?? 0) + 1;

    return {
      asset,
      securityScore: score,
      history: history.points,
      findings: { open: findings.length, byCategory, items: findings },
      exposure: {
        scanId: lastPortScan?.id ?? null,
        scannedAt: lastPortScan?.finishedAt ?? null,
        targetAddress: lastPortScan?.targetAddress ?? null,
        openPorts: lastPortScan?.ports ?? [],
      },
      latestScans: scansByType,
    };
  }

  /** 8.3 Gráfica histórica de postura de la organización (últimos 30 días por defecto). */
  async history(organizationId: string, days = 30) {
    const from = new Date(Date.now() - days * DAY_MS);
    const result = await this.riskScores.history(organizationId, { from, granularity: 'day' });
    return { days, scope: RiskScoreScope.ORGANIZATION, points: result.points };
  }
}
