import { NotFoundException } from '@nestjs/common';
import { FindingSeverity, RiskScoreScope, RiskScoreTrigger } from '@prisma/client';
import { PrismaService } from '../prisma/prisma.service';
import { RiskScoresService } from './risk-scores.service';

describe('RiskScoresService - history & anomaly detection', () => {
  let service: RiskScoresService;
  let prismaMock: {
    asset: { findFirst: jest.Mock; findUnique: jest.Mock; findMany: jest.Mock };
    riskScore: { findMany: jest.Mock; create: jest.Mock };
    scan: { findFirst: jest.Mock };
    finding: { groupBy: jest.Mock };
    $transaction: jest.Mock;
  };

  beforeEach(() => {
    prismaMock = {
      asset: {
        findFirst: jest.fn(),
        findUnique: jest.fn(),
        findMany: jest.fn(),
      },
      riskScore: {
        findMany: jest.fn(),
        create: jest.fn(),
      },
      scan: {
        findFirst: jest.fn(),
      },
      finding: {
        groupBy: jest.fn(),
      },
      $transaction: jest.fn(),
    };

    service = new RiskScoresService(prismaMock as unknown as PrismaService);
  });

  it('lanza NotFoundException si el assetId especificado no existe en la organización', async () => {
    prismaMock.asset.findFirst.mockResolvedValueOnce(null);

    await expect(
      service.history('org-1', { assetId: 'non-existent', granularity: 'day' }),
    ).rejects.toThrow(NotFoundException);
  });

  it('devuelve histórico y detecta anomalías en caídas de score', async () => {
    prismaMock.asset.findFirst.mockResolvedValueOnce({ id: 'asset-1' });

    const baseDate = new Date('2026-10-01T12:00:00.000Z');
    // 5 instantáneas: 90 -> 91 -> 90 -> 89 -> 68 (caída de 21 puntos: anomalía HIGH)
    const snapshots = [
      {
        id: 's1',
        computedAt: new Date(baseDate.getTime()),
        score: 90,
        grade: 'A',
        criticalCount: 0,
        highCount: 0,
        mediumCount: 2,
        lowCount: 2,
        infoCount: 0,
        trigger: RiskScoreTrigger.SCAN_COMPLETED,
        scanId: 'scan-1',
      },
      {
        id: 's2',
        computedAt: new Date(baseDate.getTime() + 86400000),
        score: 91,
        grade: 'A',
        criticalCount: 0,
        highCount: 0,
        mediumCount: 2,
        lowCount: 1,
        infoCount: 0,
        trigger: RiskScoreTrigger.SCAN_COMPLETED,
        scanId: 'scan-2',
      },
      {
        id: 's3',
        computedAt: new Date(baseDate.getTime() + 86400000 * 2),
        score: 90,
        grade: 'A',
        criticalCount: 0,
        highCount: 0,
        mediumCount: 2,
        lowCount: 2,
        infoCount: 0,
        trigger: RiskScoreTrigger.SCAN_COMPLETED,
        scanId: 'scan-3',
      },
      {
        id: 's4',
        computedAt: new Date(baseDate.getTime() + 86400000 * 3),
        score: 89,
        grade: 'B',
        criticalCount: 0,
        highCount: 1,
        mediumCount: 0,
        lowCount: 1,
        infoCount: 0,
        trigger: RiskScoreTrigger.SCAN_COMPLETED,
        scanId: 'scan-4',
      },
      {
        id: 's5',
        computedAt: new Date(baseDate.getTime() + 86400000 * 4),
        score: 68,
        grade: 'C',
        criticalCount: 1,
        highCount: 1,
        mediumCount: 1,
        lowCount: 0,
        infoCount: 0,
        trigger: RiskScoreTrigger.SCAN_COMPLETED,
        scanId: 'scan-5',
      },
    ];

    prismaMock.riskScore.findMany.mockResolvedValueOnce(snapshots);

    const result = await service.history('org-1', { assetId: 'asset-1', granularity: 'raw' });

    expect(result.scope).toBe(RiskScoreScope.ASSET);
    expect(result.points).toHaveLength(5);

    // Los primeros 4 puntos no son anomalías
    expect(result.points[0].anomaly).toBeNull();
    expect(result.points[1].anomaly).toBeNull();
    expect(result.points[2].anomaly).toBeNull();
    expect(result.points[3].anomaly).toBeNull();

    // El quinto punto registra la caída de 21 puntos y se clasifica como anomalía HIGH
    const lastPoint = result.points[4];
    expect(lastPoint.anomaly).not.toBeNull();
    expect(lastPoint.anomaly?.drop).toBe(21);
    expect(lastPoint.anomaly?.severity).toBe(FindingSeverity.HIGH);
    expect(lastPoint.anomaly?.zScore).toBeGreaterThanOrEqual(2.0);
  });
});
