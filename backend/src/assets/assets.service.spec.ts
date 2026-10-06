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
      },
      $transaction: jest.fn(),
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
});

