import { Injectable, NotFoundException } from '@nestjs/common';
import { FindingStatus, Prisma, RiskScore, RiskScoreScope, RiskScoreTrigger, ScanStatus } from '@prisma/client';
import { PrismaService } from '../prisma/prisma.service';
import { HistoryQuery } from './dto/history.query';
import { aggregateScores, computeScore, emptyCounts, gradeFor, ScoreResult, SeverityCounts } from './scoring';

type Db = Prisma.TransactionClient | PrismaService;

export interface AssetScoreState {
  assetId: string;
  scored: boolean;
  result: ScoreResult;
}

export interface SnapshotInput {
  organizationId: string;
  assetId: string;
  trigger: RiskScoreTrigger;
  scanId?: string;
}

const snapshotSelect = {
  id: true,
  scope: true,
  assetId: true,
  score: true,
  grade: true,
  criticalCount: true,
  highCount: true,
  mediumCount: true,
  lowCount: true,
  infoCount: true,
  scoredAssets: true,
  breakdown: true,
  trigger: true,
  scanId: true,
  computedAt: true,
} satisfies Prisma.RiskScoreSelect;

export type Snapshot = Prisma.RiskScoreGetPayload<{ select: typeof snapshotSelect }>;

function assetSnapshotData(organizationId: string, state: AssetScoreState, trigger: RiskScoreTrigger, scanId?: string) {
  return {
    organizationId,
    scope: RiskScoreScope.ASSET,
    assetId: state.assetId,
    score: state.scored ? state.result.score : null,
    grade: state.scored ? state.result.grade : null,
    ...countsToColumns(state.result.counts),
    breakdown: {
      modelVersion: state.result.modelVersion,
      totalPenalty: state.result.totalPenalty,
      penalties: state.result.penalties,
    } as unknown as Prisma.InputJsonValue,
    trigger,
    scanId,
  };
}

function countsToColumns(c: SeverityCounts) {
  return {
    criticalCount: c.CRITICAL,
    highCount: c.HIGH,
    mediumCount: c.MEDIUM,
    lowCount: c.LOW,
    infoCount: c.INFO,
  };
}

/**
 * Cálculo y persistencia del Security Score (RF-07) y del histórico de
 * postura (RF-11). Todas las consultas se filtran por organización.
 */
@Injectable()
export class RiskScoresService {
  constructor(private readonly prisma: PrismaService) {}

  /** Conteo de hallazgos OPEN por severidad para un activo o toda la organización. */
  async openCounts(db: Db, organizationId: string, assetId?: string): Promise<SeverityCounts> {
    const rows = await db.finding.groupBy({
      by: ['severity'],
      where: { organizationId, assetId, status: FindingStatus.OPEN },
      _count: { id: true },
    });
    const counts = emptyCounts();
    for (const row of rows) counts[row.severity] = row._count.id;
    return counts;
  }

  /** Un activo se evalúa solo si tiene al menos un escaneo completado. */
  private async isScored(db: Db, assetId: string): Promise<boolean> {
    const scan = await db.scan.findFirst({
      where: { assetId, status: ScanStatus.COMPLETED },
      select: { id: true },
    });
    return scan !== null;
  }

  async computeAsset(db: Db, organizationId: string, assetId: string): Promise<AssetScoreState> {
    const [scored, counts] = await Promise.all([
      this.isScored(db, assetId),
      this.openCounts(db, organizationId, assetId),
    ]);
    return { assetId, scored, result: computeScore(counts) };
  }

  /** Score de todos los activos activos de la organización (evaluados o no). */
  async computeAllAssets(db: Db, organizationId: string): Promise<AssetScoreState[]> {
    const assets = await db.asset.findMany({
      where: { organizationId, isActive: true },
      select: {
        id: true,
        scans: { where: { status: ScanStatus.COMPLETED }, select: { id: true }, take: 1 },
        findings: { where: { status: FindingStatus.OPEN }, select: { severity: true } },
      },
    });
    return assets.map((a) => {
      const counts = emptyCounts();
      for (const f of a.findings) counts[f.severity] += 1;
      return { assetId: a.id, scored: a.scans.length > 0, result: computeScore(counts) };
    });
  }

  /**
   * Registra una instantánea del activo y otra de la organización.
   * Se invoca dentro de la transacción del evento que cambió los datos.
   */
  async snapshot(db: Db, input: SnapshotInput): Promise<{ asset: Snapshot; organization: Snapshot }> {
    const assetState = await this.computeAsset(db, input.organizationId, input.assetId);
    const asset = await db.riskScore.create({
      data: assetSnapshotData(input.organizationId, assetState, input.trigger, input.scanId),
      select: snapshotSelect,
    });
    const organization = await this.snapshotOrganization(db, input.organizationId, input.trigger, input.scanId);
    return { asset, organization };
  }

  async snapshotOrganization(
    db: Db,
    organizationId: string,
    trigger: RiskScoreTrigger,
    scanId?: string,
  ): Promise<Snapshot> {
    const states = await this.computeAllAssets(db, organizationId);
    const scored = states.filter((s) => s.scored);
    const score = aggregateScores(scored.map((s) => s.result.score));
    const counts = emptyCounts();
    for (const s of scored) {
      for (const sev of Object.keys(counts) as Array<keyof SeverityCounts>) counts[sev] += s.result.counts[sev];
    }
    return db.riskScore.create({
      data: {
        organizationId,
        scope: RiskScoreScope.ORGANIZATION,
        score,
        grade: score === null ? null : gradeFor(score).grade,
        ...countsToColumns(counts),
        scoredAssets: scored.length,
        breakdown: {
          modelVersion: computeScore({}).modelVersion,
          method: 'mean-of-asset-scores',
          assets: scored.map((s) => ({ assetId: s.assetId, score: s.result.score, grade: s.result.grade })),
        } as Prisma.InputJsonValue,
        trigger,
        scanId,
      },
      select: snapshotSelect,
    });
  }

  /** Recalcula y registra instantáneas de todos los activos y de la organización. */
  async recalculate(organizationId: string, trigger: RiskScoreTrigger = RiskScoreTrigger.MANUAL) {
    return this.prisma.$transaction(async (tx) => {
      const assets = await tx.asset.findMany({ where: { organizationId, isActive: true }, select: { id: true } });
      let assetSnapshots = 0;
      for (const a of assets) {
        const state = await this.computeAsset(tx, organizationId, a.id);
        await tx.riskScore.create({ data: assetSnapshotData(organizationId, state, trigger) });
        assetSnapshots += 1;
      }
      const organization = await this.snapshotOrganization(tx, organizationId, trigger);
      return { organization, assetSnapshots };
    });
  }

  /** Última instantánea registrada del ámbito indicado. */
  async latest(organizationId: string, assetId?: string): Promise<Snapshot | null> {
    return this.prisma.riskScore.findFirst({
      where: assetId
        ? { organizationId, scope: RiskScoreScope.ASSET, assetId }
        : { organizationId, scope: RiskScoreScope.ORGANIZATION },
      orderBy: { computedAt: 'desc' },
      select: snapshotSelect,
    });
  }

  /** Última instantánea anterior a una fecha (para calcular tendencias). */
  async latestBefore(organizationId: string, before: Date, assetId?: string): Promise<Snapshot | null> {
    return this.prisma.riskScore.findFirst({
      where: {
        organizationId,
        scope: assetId ? RiskScoreScope.ASSET : RiskScoreScope.ORGANIZATION,
        assetId: assetId ?? null,
        computedAt: { lt: before },
      },
      orderBy: { computedAt: 'desc' },
      select: snapshotSelect,
    });
  }

  /**
   * Score actual calculado en vivo (no la última instantánea), con el desglose
   * de la fórmula para explicar la puntuación al usuario.
   */
  async current(organizationId: string, assetId?: string) {
    if (assetId) {
      const asset = await this.prisma.asset.findFirst({
        where: { id: assetId, organizationId },
        select: { id: true, value: true, name: true, type: true, lastScannedAt: true },
      });
      if (!asset) throw new NotFoundException('Activo no encontrado');
      const state = await this.computeAsset(this.prisma, organizationId, assetId);
      return {
        scope: RiskScoreScope.ASSET,
        asset,
        scored: state.scored,
        score: state.scored ? state.result.score : null,
        grade: state.scored ? state.result.grade : null,
        label: state.scored ? state.result.label : 'Sin evaluar',
        description: state.scored ? state.result.description : 'El activo todavía no tiene ningún escaneo completado.',
        counts: state.result.counts,
        penalties: state.result.penalties,
        totalPenalty: state.result.totalPenalty,
        modelVersion: state.result.modelVersion,
      };
    }

    const states = await this.computeAllAssets(this.prisma, organizationId);
    const scored = states.filter((s) => s.scored);
    const score = aggregateScores(scored.map((s) => s.result.score));
    const counts = emptyCounts();
    for (const s of scored) {
      for (const sev of Object.keys(counts) as Array<keyof SeverityCounts>) counts[sev] += s.result.counts[sev];
    }
    const band = score === null ? null : gradeFor(score);
    return {
      scope: RiskScoreScope.ORGANIZATION,
      score,
      grade: band?.grade ?? null,
      label: band?.label ?? 'Sin evaluar',
      description: band?.description ?? 'Ningún activo tiene todavía un escaneo completado.',
      counts,
      scoredAssets: scored.length,
      totalAssets: states.length,
      modelVersion: computeScore({}).modelVersion,
    };
  }

  /** Histórico de postura (RF-11). */
  async history(organizationId: string, query: HistoryQuery) {
    if (query.assetId) {
      const exists = await this.prisma.asset.findFirst({ where: { id: query.assetId, organizationId }, select: { id: true } });
      if (!exists) throw new NotFoundException('Activo no encontrado');
    }
    const rows = await this.prisma.riskScore.findMany({
      where: {
        organizationId,
        scope: query.assetId ? RiskScoreScope.ASSET : RiskScoreScope.ORGANIZATION,
        assetId: query.assetId ?? null,
        computedAt: { gte: query.from, lte: query.to },
      },
      orderBy: { computedAt: 'asc' },
      select: snapshotSelect,
      take: 2000,
    });
    const points = query.granularity === 'raw' ? rows : collapseByDay(rows);
    return {
      scope: query.assetId ? RiskScoreScope.ASSET : RiskScoreScope.ORGANIZATION,
      assetId: query.assetId ?? null,
      granularity: query.granularity,
      from: query.from ?? null,
      to: query.to ?? null,
      points: points.map((p) => ({
        computedAt: p.computedAt,
        score: p.score,
        grade: p.grade,
        counts: { CRITICAL: p.criticalCount, HIGH: p.highCount, MEDIUM: p.mediumCount, LOW: p.lowCount, INFO: p.infoCount },
        trigger: p.trigger,
        scanId: p.scanId,
      })),
    };
  }
}

/** Conserva la última instantánea de cada día (UTC). */
function collapseByDay<T extends Pick<RiskScore, 'computedAt'>>(rows: T[]): T[] {
  const byDay = new Map<string, T>();
  for (const row of rows) byDay.set(row.computedAt.toISOString().slice(0, 10), row);
  return [...byDay.values()];
}
