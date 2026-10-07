import { ConfigService } from '@nestjs/config';
import { AssetCriticality, AssetType } from '@prisma/client';
import { AssetsService } from './assets.service';
import { PrismaService } from '../prisma/prisma.service';
import { RiskScoresService } from '../risk/risk-scores.service';
import { AssetVerificationService } from './verification/asset-verification.service';
import { AuditService } from '../audit/audit.service';
import { AuthUser } from '../common/interfaces/auth-user.interface';

describe('AssetsService', () => {
  let service: AssetsService;
  let prisma: {
    asset: {
      create: jest.Mock;
      findMany: jest.Mock;
      count: jest.Mock;
      findFirst: jest.Mock;
      update: jest.Mock;
      delete: jest.Mock;
    };
    scan: {
      count: jest.Mock;
      groupBy: jest.Mock;
    };
    finding: {
      count: jest.Mock;
      groupBy: jest.Mock;
    };
    scanPort: {
      findMany: jest.Mock;
    };
    discoveredHost: {
      count: jest.Mock;
    };
    riskScore: {
      findFirst: jest.Mock;
    };
    $transaction: jest.Mock;
  };
  let config: jest.Mocked<ConfigService>;
  let riskScores: jest.Mocked<RiskScoresService>;
  let verification: jest.Mocked<AssetVerificationService>;
  let audit: jest.Mocked<AuditService>;

  const mockActor: AuthUser = {
    id: 'user-1',
    organizationId: 'org-1',
    email: 'admin@org.com',
    role: 'ADMIN',
    fullName: 'Admin User',
  };

  beforeEach(() => {
    prisma = {
      asset: {
        create: jest.fn(),
        findMany: jest.fn(),
        count: jest.fn(),
        findFirst: jest.fn(),
        update: jest.fn(),
        delete: jest.fn(),
      },
      scan: {
        count: jest.fn().mockResolvedValue(0),
        groupBy: jest.fn().mockResolvedValue([]),
      },
      finding: {
        count: jest.fn().mockResolvedValue(0),
        groupBy: jest.fn().mockResolvedValue([]),
      },
      scanPort: {
        findMany: jest.fn().mockResolvedValue([]),
      },
      discoveredHost: {
        count: jest.fn().mockResolvedValue(0),
      },
      riskScore: {
        findFirst: jest.fn().mockResolvedValue(null),
      },
      $transaction: jest.fn(async (callback: any) => {
        if (typeof callback === 'function') {
          return callback(prisma);
        }
        return callback;
      }),
    };
    config = {
      get: jest.fn().mockReturnValue(false),
    } as unknown as jest.Mocked<ConfigService>;
    riskScores = {
      snapshotOrganization: jest.fn(),
    } as unknown as jest.Mocked<RiskScoresService>;
    verification = {
      inheritedVerification: jest.fn().mockResolvedValue(null),
    } as unknown as jest.Mocked<AssetVerificationService>;
    audit = {
      record: jest.fn(),
    } as unknown as jest.Mocked<AuditService>;

    service = new AssetsService(
      prisma as unknown as PrismaService,
      config,
      riskScores,
      verification,
      audit,
    );
  });

  it('crea un activo con criticidad y tags personalizados', async () => {
    prisma.asset.create.mockResolvedValue({
      id: 'asset-1',
      organizationId: 'org-1',
      type: AssetType.DOMAIN,
      value: 'empresa.com',
      criticality: AssetCriticality.HIGH,
      tags: ['produccion', 'core'],
    });

    const result = await service.create(mockActor, {
      value: 'empresa.com',
      authorizationConfirmed: true,
      criticality: AssetCriticality.HIGH,
      tags: ['produccion', 'core'],
    });

    expect(prisma.asset.create).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({
          criticality: AssetCriticality.HIGH,
          tags: ['produccion', 'core'],
        }),
      }),
    );
    expect(result.criticality).toBe(AssetCriticality.HIGH);
  });

  it('asigna criticidad MEDIUM por defecto si no se especifica', async () => {
    prisma.asset.create.mockResolvedValue({
      id: 'asset-2',
      organizationId: 'org-1',
      type: AssetType.DOMAIN,
      value: 'app.empresa.com',
      criticality: AssetCriticality.MEDIUM,
      tags: [],
    });

    await service.create(mockActor, {
      value: 'app.empresa.com',
      authorizationConfirmed: true,
    });

    expect(prisma.asset.create).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({
          criticality: AssetCriticality.MEDIUM,
          tags: [],
        }),
      }),
    );
  });

  it('filtra activos por criticidad y tag en findAll', async () => {
    prisma.$transaction.mockResolvedValue([[], 0]);

    await service.findAll('org-1', {
      page: 1,
      pageSize: 20,
      criticality: AssetCriticality.CRITICAL,
      tag: 'pci-dss',
    });

    expect(prisma.$transaction).toHaveBeenCalled();
    expect(prisma.asset.findMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: expect.objectContaining({
          criticality: AssetCriticality.CRITICAL,
          tags: { has: 'pci-dss' },
        }),
      }),
    );
  });

  describe('exportStream', () => {
    async function readStream(stream: NodeJS.ReadableStream): Promise<string> {
      const chunks: Buffer[] = [];
      for await (const chunk of stream) {
        chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
      }
      return Buffer.concat(chunks).toString('utf-8');
    }

    it('exporta inventario de activos en formato CSV con BOM y cabeceras', async () => {
      (riskScores as any).computeAllAssets = jest.fn().mockResolvedValue([
        {
          assetId: 'a-1',
          scored: true,
          result: { score: 85 },
        },
      ]);

      prisma.asset.findMany
        .mockResolvedValueOnce([
          {
            id: 'a-1',
            name: 'Portal Web',
            value: 'portal.empresa.com',
            type: AssetType.DOMAIN,
            criticality: AssetCriticality.HIGH,
            tags: ['web', 'public'],
            isActive: true,
            verifiedAt: new Date('2026-09-01T00:00:00.000Z'),
            verificationMethod: 'DNS_TXT',
            lastScannedAt: new Date('2026-10-05T12:00:00.000Z'),
            createdAt: new Date('2026-09-01T00:00:00.000Z'),
          },
          {
            id: 'a-2',
            name: null,
            value: '198.51.100.10',
            type: AssetType.IP,
            criticality: AssetCriticality.LOW,
            tags: [],
            isActive: false,
            verifiedAt: null,
            verificationMethod: null,
            lastScannedAt: null,
            createdAt: new Date('2026-09-10T00:00:00.000Z'),
          },
        ])
        .mockResolvedValueOnce([]);

      const stream = service.exportStream('org-1', {});
      const csv = await readStream(stream);

      expect(csv.startsWith('\uFEFF')).toBe(true);
      const lines = csv.slice(1).trim().split('\r\n');
      expect(lines).toHaveLength(3);
      expect(lines[0]).toBe(
        'id,name,value,type,criticality,tags,is_active,verified,verification_method,score,grade,last_scanned_at,created_at',
      );

      // Asset 1: scored 85 -> Grade B
      expect(lines[1]).toContain('a-1,Portal Web,portal.empresa.com,DOMAIN,HIGH,"web, public",true,true,DNS_TXT,85,B');
      expect(lines[1]).toContain('2026-10-05T12:00:00.000Z');

      // Asset 2: inactive, unverified, unscored
      expect(lines[2]).toContain('a-2,,198.51.100.10,IP,LOW,,false,false,,,,,2026-09-10T00:00:00.000Z');
    });

    it('aplica filtros de tipo, criticidad, tag y activo/inactivo', async () => {
      (riskScores as any).computeAllAssets = jest.fn().mockResolvedValue([]);
      prisma.asset.findMany.mockResolvedValueOnce([]);

      const stream = service.exportStream('org-1', {
        type: AssetType.DOMAIN,
        criticality: AssetCriticality.CRITICAL,
        tag: 'prod',
        isActive: true,
        search: 'api',
      });
      await readStream(stream);

      expect(prisma.asset.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({
            organizationId: 'org-1',
            type: AssetType.DOMAIN,
            criticality: AssetCriticality.CRITICAL,
            tags: { has: 'prod' },
            isActive: true,
          }),
        }),
      );
    });
  });

  describe('remove', () => {
    it('elimina el activo y registra en auditoría el balance inmutable de presencia y acciones', async () => {
      const existingAsset = {
        id: 'asset-to-delete',
        organizationId: 'org-1',
        value: 'antiguo.empresa.com',
        name: 'Servidor Legacy',
        type: AssetType.DOMAIN,
        criticality: AssetCriticality.HIGH,
        tags: ['legacy', 'migracion'],
        createdAt: new Date('2026-01-15T00:00:00.000Z'),
        verifiedAt: new Date('2026-01-15T01:00:00.000Z'),
        verificationMethod: 'DNS_TXT',
        lastScannedAt: new Date('2026-10-01T10:00:00.000Z'),
      };

      prisma.asset.findFirst.mockResolvedValueOnce(existingAsset);
      prisma.scan.count.mockResolvedValueOnce(8);
      prisma.scan.groupBy.mockResolvedValueOnce([
        { type: 'PORT_SCAN', _count: { _all: 4 } },
        { type: 'WEB_HEADERS', _count: { _all: 4 } },
      ]);
      prisma.finding.count.mockResolvedValueOnce(3);
      prisma.finding.groupBy
        .mockResolvedValueOnce([
          { severity: 'HIGH', _count: { _all: 1 } },
          { severity: 'MEDIUM', _count: { _all: 2 } },
        ])
        .mockResolvedValueOnce([
          { status: 'OPEN', _count: { _all: 2 } },
          { status: 'RESOLVED', _count: { _all: 1 } },
        ]);
      prisma.scanPort.findMany.mockResolvedValueOnce([
        { port: 80, protocol: 'tcp', serviceName: 'http' },
        { port: 443, protocol: 'tcp', serviceName: 'https' },
      ]);
      prisma.discoveredHost.count.mockResolvedValueOnce(2);
      prisma.riskScore.findFirst.mockResolvedValueOnce({ score: 72, grade: 'C' });

      await service.remove(mockActor, 'asset-to-delete', {
        reason: 'Servidor decomisado por obsolescencia',
      });

      expect(prisma.asset.delete).toHaveBeenCalledWith({ where: { id: 'asset-to-delete' } });
      expect(riskScores.snapshotOrganization).toHaveBeenCalledWith(
        expect.anything(),
        'org-1',
        expect.anything(),
      );

      expect(audit.record).toHaveBeenCalledWith({
        organizationId: 'org-1',
        action: 'asset.delete',
        actor: mockActor,
        target: { type: 'asset', id: 'asset-to-delete', label: 'antiguo.empresa.com' },
        detail: expect.objectContaining({
          assetValue: 'antiguo.empresa.com',
          assetName: 'Servidor Legacy',
          assetType: AssetType.DOMAIN,
          criticality: AssetCriticality.HIGH,
          tags: ['legacy', 'migracion'],
          registeredAt: '2026-01-15T00:00:00.000Z',
          verified: true,
          verificationMethod: 'DNS_TXT',
          reason: 'Servidor decomisado por obsolescencia',
          totalScans: 8,
          scansByType: { PORT_SCAN: 4, WEB_HEADERS: 4 },
          totalFindings: 3,
          findingsBySeverity: { HIGH: 1, MEDIUM: 2 },
          findingsByStatus: { OPEN: 2, RESOLVED: 1 },
          openPorts: ['80/tcp (http)', '443/tcp (https)'],
          discoveredSubdomainsCount: 2,
          lastScore: '72 (C)',
        }),
      });
    });
  });
});

