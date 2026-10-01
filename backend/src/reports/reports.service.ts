import { Injectable, NotFoundException } from '@nestjs/common';
import { FindingStatus, Prisma, ReportType, ScanStatus, ScanType } from '@prisma/client';
import { AuthUser } from '../common/interfaces/auth-user.interface';
import { PrismaService } from '../prisma/prisma.service';
import { RiskScoresService } from '../risk/risk-scores.service';
import { computeScore, emptyCounts } from '../risk/scoring';
import { renderReport } from './pdf-renderer';
import { ReportAsset, ReportData, severityRank } from './report-data';

const DAY_MS = 24 * 60 * 60 * 1000;

const findingSelect = {
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
} satisfies Prisma.FindingSelect;

export interface GeneratedReport {
  filename: string;
  buffer: Buffer;
}

function slugify(text: string): string {
  return (
    text
      .normalize('NFD')
      .replace(/[̀-ͯ]/g, '')
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .slice(0, 50) || 'organizacion'
  );
}

/**
 * Reportes PDF (RF-09, sección 9): ejecutivo para gerencia y técnico para el
 * equipo de TI, de toda la organización o de un activo. Se generan bajo
 * demanda con los datos vigentes y se registra cada generación.
 */
@Injectable()
export class ReportsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly riskScores: RiskScoresService,
  ) {}

  async gather(actor: AuthUser, type: ReportType, assetId?: string): Promise<ReportData> {
    const organizationId = actor.organizationId;
    const now = new Date();
    const org = await this.prisma.organization.findUniqueOrThrow({ where: { id: organizationId }, select: { name: true } });

    let scopeAsset: { value: string; name: string | null } | null = null;
    if (assetId) {
      scopeAsset = await this.prisma.asset.findFirst({ where: { id: assetId, organizationId }, select: { value: true, name: true } });
      if (!scopeAsset) throw new NotFoundException('Activo no encontrado');
    }

    const [current, weekBefore, history, rows, alertsLast30, alertsPending] = await Promise.all([
      this.riskScores.current(organizationId, assetId),
      this.riskScores.latestBefore(organizationId, new Date(now.getTime() - 7 * DAY_MS), assetId),
      this.riskScores.history(organizationId, { assetId, from: new Date(now.getTime() - 30 * DAY_MS), granularity: 'day' }),
      this.prisma.asset.findMany({
        where: assetId ? { id: assetId, organizationId } : { organizationId, isActive: true },
        orderBy: { createdAt: 'asc' },
        select: {
          id: true,
          type: true,
          value: true,
          name: true,
          isActive: true,
          lastScannedAt: true,
          findings: {
            where: { status: { in: [FindingStatus.OPEN, FindingStatus.ACCEPTED, FindingStatus.FALSE_POSITIVE] } },
            select: findingSelect,
          },
          scans: {
            where: { status: ScanStatus.COMPLETED },
            orderBy: { finishedAt: 'desc' },
            select: { type: true, finishedAt: true },
          },
        },
      }),
      this.prisma.alert.count({
        where: { organizationId, assetId, createdAt: { gte: new Date(now.getTime() - 30 * DAY_MS) } },
      }),
      this.prisma.alert.count({ where: { organizationId, assetId, acknowledgedAt: null } }),
    ]);

    const assets: ReportAsset[] = [];
    for (const row of rows) {
      const open = row.findings
        .filter((f) => f.status === FindingStatus.OPEN)
        .sort((a, b) => severityRank(a.severity) - severityRank(b.severity) || Number(b.cvssScore ?? 0) - Number(a.cvssScore ?? 0));
      const counts = emptyCounts();
      for (const f of open) counts[f.severity] += 1;
      const scored = row.scans.length > 0;
      const result = computeScore(counts);
      const lastScanByType: Partial<Record<ScanType, Date | null>> = {};
      for (const s of row.scans) if (!(s.type in lastScanByType)) lastScanByType[s.type] = s.finishedAt;

      const portScan = await this.prisma.scan.findFirst({
        where: { assetId: row.id, type: ScanType.PORT_SCAN, status: ScanStatus.COMPLETED },
        orderBy: { finishedAt: 'desc' },
        select: {
          finishedAt: true,
          ports: {
            where: { state: 'open' },
            orderBy: { port: 'asc' },
            select: { port: true, protocol: true, serviceName: true, product: true, version: true },
          },
        },
      });

      assets.push({
        id: row.id,
        type: row.type,
        value: row.value,
        name: row.name,
        isActive: row.isActive,
        scored,
        score: scored ? result.score : null,
        grade: scored ? result.grade : null,
        counts,
        lastScannedAt: row.lastScannedAt,
        lastScanByType,
        openPorts: portScan?.ports ?? [],
        portScanAt: portScan?.finishedAt ?? null,
        findings: open.map((f) => ({
          ...f,
          cvssScore: f.cvssScore === null ? null : Number(f.cvssScore),
          evidence: (f.evidence ?? null) as Record<string, unknown> | null,
        })),
        excluded: {
          accepted: row.findings.filter((f) => f.status === FindingStatus.ACCEPTED).length,
          falsePositive: row.findings.filter((f) => f.status === FindingStatus.FALSE_POSITIVE).length,
        },
      });
    }

    const currentOrg = current as { scoredAssets?: number; totalAssets?: number };
    return {
      type,
      generatedAt: now,
      generatedBy: actor.fullName,
      organizationName: org.name,
      scope: scopeAsset ? { kind: 'ASSET', value: scopeAsset.value, name: scopeAsset.name } : { kind: 'ORGANIZATION' },
      score: {
        score: current.score,
        grade: current.grade,
        label: current.label,
        description: current.description,
        counts: current.counts,
        scoredAssets: currentOrg.scoredAssets ?? (current.score === null ? 0 : 1),
        totalAssets: currentOrg.totalAssets ?? 1,
        weekAgoScore: weekBefore?.score ?? null,
      },
      history: history.points.map((p) => ({ date: p.computedAt, score: p.score })),
      assets,
      alerts: { last30Days: alertsLast30, unacknowledged: alertsPending },
    };
  }

  async generate(actor: AuthUser, type: ReportType, assetId?: string): Promise<GeneratedReport> {
    const data = await this.gather(actor, type, assetId);
    const { buffer, pages } = await renderReport(data);
    await this.prisma.report.create({
      data: {
        organizationId: actor.organizationId,
        assetId: assetId ?? null,
        type,
        generatedById: actor.id,
        score: data.score.score,
        grade: data.score.grade,
        openFindings: Object.values(data.score.counts).reduce((acc, n) => acc + n, 0),
        pages,
        sizeBytes: buffer.length,
      },
    });
    const kind = type === ReportType.EXECUTIVE ? 'ejecutivo' : 'tecnico';
    const subject = slugify(data.scope.kind === 'ASSET' ? data.scope.value : data.organizationName);
    const date = data.generatedAt.toISOString().slice(0, 10).replace(/-/g, '');
    return { filename: `sspm-reporte-${kind}-${subject}-${date}.pdf`, buffer };
  }

  /** Historial de reportes generados (los más recientes primero). */
  async list(organizationId: string) {
    const items = await this.prisma.report.findMany({
      where: { organizationId },
      orderBy: { createdAt: 'desc' },
      take: 50,
      select: {
        id: true,
        type: true,
        score: true,
        grade: true,
        openFindings: true,
        pages: true,
        sizeBytes: true,
        createdAt: true,
        asset: { select: { id: true, value: true, name: true } },
        generatedBy: { select: { id: true, fullName: true } },
      },
    });
    return { items };
  }
}
