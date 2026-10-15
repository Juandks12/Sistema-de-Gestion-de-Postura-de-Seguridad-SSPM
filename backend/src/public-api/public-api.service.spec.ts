import { Test, TestingModule } from '@nestjs/testing';
import { FindingSeverity, FindingStatus } from '@prisma/client';
import { PrismaService } from '../prisma/prisma.service';
import { RiskScoresService } from '../risk/risk-scores.service';
import { PublicApiService } from './public-api.service';

describe('PublicApiService', () => {
  let service: PublicApiService;
  let prisma: {
    finding: { findMany: jest.Mock };
    alert: { findMany: jest.Mock };
    asset: { count: jest.Mock; findMany: jest.Mock };
  };
  let riskScores: { latest: jest.Mock };

  beforeEach(async () => {
    prisma = {
      finding: { findMany: jest.fn() },
      alert: { findMany: jest.fn() },
      asset: { count: jest.fn(), findMany: jest.fn() },
    };
    riskScores = {
      latest: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        PublicApiService,
        { provide: PrismaService, useValue: prisma },
        { provide: RiskScoresService, useValue: riskScores },
      ],
    }).compile();

    service = module.get<PublicApiService>(PublicApiService);
  });

  describe('getFindings', () => {
    it('debe filtrar hallazgos por organización y cursor since', async () => {
      const mockFindings = [
        { id: 'f-1', ruleId: 'R-1', title: 'TLS Expired', severity: FindingSeverity.HIGH },
      ];
      prisma.finding.findMany.mockResolvedValue(mockFindings);

      const res = await service.getFindings('org-1', {
        since: '2026-10-01T00:00:00Z',
        severity: FindingSeverity.HIGH,
        status: FindingStatus.OPEN,
        limit: 50,
      });

      expect(res.total).toBe(1);
      expect(res.since).toBe('2026-10-01T00:00:00Z');
      expect(res.items).toBe(mockFindings);
      expect(prisma.finding.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({
            organizationId: 'org-1',
            severity: FindingSeverity.HIGH,
            status: FindingStatus.OPEN,
            updatedAt: { gte: new Date('2026-10-01T00:00:00Z') },
          }),
          take: 50,
        }),
      );
    });
  });

  describe('getAlerts', () => {
    it('debe filtrar alertas por organización y severidad', async () => {
      const mockAlerts = [{ id: 'a-1', title: 'Port Open', severity: FindingSeverity.CRITICAL }];
      prisma.alert.findMany.mockResolvedValue(mockAlerts);

      const res = await service.getAlerts('org-1', {
        severity: FindingSeverity.CRITICAL,
        limit: 20,
      });

      expect(res.total).toBe(1);
      expect(res.items).toBe(mockAlerts);
    });
  });

  describe('getPosture', () => {
    it('debe retornar la última postura de la organización y el conteo de activos', async () => {
      riskScores.latest.mockResolvedValue({
        score: 85,
        grade: 'A',
        computedAt: new Date('2026-10-14T10:00:00Z'),
        trigger: 'SCAN_COMPLETED',
        scoredAssets: 4,
        criticalCount: 0,
        highCount: 1,
        mediumCount: 2,
        lowCount: 3,
        infoCount: 0,
        breakdown: { modelVersion: '1.0' },
      });
      prisma.asset.count.mockResolvedValue(5);

      const posture = await service.getPosture('org-1');
      expect(posture).toEqual({
        organizationId: 'org-1',
        score: 85,
        grade: 'A',
        computedAt: new Date('2026-10-14T10:00:00Z'),
        trigger: 'SCAN_COMPLETED',
        totalAssets: 5,
        scoredAssets: 4,
        findingsSummary: {
          critical: 0,
          high: 1,
          medium: 2,
          low: 3,
          info: 0,
        },
        breakdown: { modelVersion: '1.0' },
      });
    });
  });

  describe('getAssets', () => {
    it('debe listar activos con resumen de severidades de hallazgos abiertos', async () => {
      prisma.asset.findMany.mockResolvedValue([
        {
          id: 'asset-1',
          type: 'DOMAIN',
          value: 'example.com',
          name: 'Main site',
          criticality: 'HIGH',
          tags: ['prod'],
          verifiedAt: new Date(),
          verificationMethod: 'DNS_TXT',
          lastScannedAt: new Date(),
          createdAt: new Date(),
          updatedAt: new Date(),
          findings: [{ severity: 'HIGH' }, { severity: 'MEDIUM' }],
        },
      ]);

      const res = await service.getAssets('org-1', { limit: 100 });
      expect(res.total).toBe(1);
      expect(res.items[0].isVerified).toBe(true);
      expect(res.items[0].openFindings).toEqual({
        critical: 0,
        high: 1,
        medium: 1,
        low: 0,
        info: 0,
        total: 2,
      });
    });
  });
});
