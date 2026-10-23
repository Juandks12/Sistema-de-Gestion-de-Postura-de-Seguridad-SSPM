import { BadRequestException, ConflictException, NotFoundException } from '@nestjs/common';
import {
  AssetType,
  DiagnosticBatchStatus,
  DiagnosticProfile,
  ScanStatus,
  ScanType,
} from '@prisma/client';
import { DiagnosticOrchestratorService } from './diagnostic-orchestrator.service';
import { AuthUser } from '../common/interfaces/auth-user.interface';

describe('DiagnosticOrchestratorService', () => {
  let service: DiagnosticOrchestratorService;
  let prismaMock: any;
  let scansServiceMock: any;
  let workerMock: any;

  const mockUser: AuthUser = {
    id: 'user-1',
    organizationId: 'org-1',
    email: 'user@example.com',
    fullName: 'Test Admin',
    role: 'ADMIN',
  };

  beforeEach(() => {
    prismaMock = {
      asset: { findFirst: jest.fn() },
      diagnosticBatch: {
        findFirst: jest.fn(),
        findUnique: jest.fn(),
        create: jest.fn(),
        update: jest.fn(),
      },
      riskScore: { findFirst: jest.fn() },
      finding: { findMany: jest.fn() },
      discoveredHost: { count: jest.fn() },
    };

    scansServiceMock = {
      enqueue: jest.fn(),
      cancel: jest.fn(),
    };

    workerMock = {
      kick: jest.fn(),
      registerCompletionHook: jest.fn(),
    };

    service = new DiagnosticOrchestratorService(prismaMock, scansServiceMock, workerMock);
  });

  describe('getStagesForProfile', () => {
    it('genera 3 etapas para perfil COMMERCE_360 sobre un dominio', () => {
      const stages = service.getStagesForProfile(DiagnosticProfile.COMMERCE_360, AssetType.DOMAIN);
      expect(stages).toHaveLength(3);
      expect(stages[0].types).toEqual([ScanType.SUBDOMAIN_DISCOVERY]);
      expect(stages[1].types).toContain(ScanType.PORT_SCAN);
      expect(stages[1].types).toContain(ScanType.EMAIL_SECURITY);
      expect(stages[2].types).toEqual([
        ScanType.WEB_HEADERS,
        ScanType.SENSITIVE_PATHS,
        ScanType.SSL_CERT,
      ]);
    });

    it('omite etapas de subdominios y correo para activos de tipo IP', () => {
      const stages = service.getStagesForProfile(DiagnosticProfile.COMMERCE_360, AssetType.IP);
      expect(stages).toHaveLength(2);
      expect(stages[0].types).toEqual([ScanType.PORT_SCAN]);
      expect(stages[1].types).toContain(ScanType.WEB_HEADERS);
    });

    it('genera 2 etapas para perfil PERIMETER_FAST', () => {
      const stages = service.getStagesForProfile(DiagnosticProfile.PERIMETER_FAST, AssetType.DOMAIN);
      expect(stages).toHaveLength(2);
      expect(stages[0].types).toEqual([ScanType.PORT_SCAN]);
      expect(stages[1].types).toEqual([ScanType.WEB_HEADERS, ScanType.SSL_CERT]);
    });
  });

  describe('start', () => {
    it('rechaza el inicio si el activo no existe o está inactivo', async () => {
      prismaMock.asset.findFirst.mockResolvedValue(null);
      await expect(service.start(mockUser, 'asset-1')).rejects.toThrow(NotFoundException);

      prismaMock.asset.findFirst.mockResolvedValue({ id: 'asset-1', isActive: false });
      await expect(service.start(mockUser, 'asset-1')).rejects.toThrow(BadRequestException);
    });

    it('rechaza si ya existe un diagnóstico 360° en progreso', async () => {
      prismaMock.asset.findFirst.mockResolvedValue({
        id: 'asset-1',
        isActive: true,
        authorizationConfirmed: true,
        type: AssetType.DOMAIN,
      });
      prismaMock.diagnosticBatch.findFirst.mockResolvedValue({
        id: 'batch-active',
        status: DiagnosticBatchStatus.IN_PROGRESS,
      });

      await expect(service.start(mockUser, 'asset-1')).rejects.toThrow(ConflictException);
    });

    it('crea el lote e inicia la primera etapa encolando escaneos', async () => {
      prismaMock.asset.findFirst.mockResolvedValue({
        id: 'asset-1',
        isActive: true,
        authorizationConfirmed: true,
        type: AssetType.DOMAIN,
      });
      prismaMock.diagnosticBatch.findFirst.mockResolvedValue(null);
      prismaMock.diagnosticBatch.create.mockResolvedValue({
        id: 'batch-1',
        assetId: 'asset-1',
        organizationId: 'org-1',
        profile: DiagnosticProfile.COMMERCE_360,
        status: DiagnosticBatchStatus.IN_PROGRESS,
        currentStage: 1,
        totalStages: 3,
      });

      // Mock para getBatch interno
      jest.spyOn(service, 'getBatch').mockResolvedValue({
        id: 'batch-1',
        status: DiagnosticBatchStatus.IN_PROGRESS,
        currentStage: 1,
        progressPercentage: 10,
        stages: [],
      } as any);

      const res = await service.start(mockUser, 'asset-1', DiagnosticProfile.COMMERCE_360);

      expect(prismaMock.diagnosticBatch.create).toHaveBeenCalled();
      expect(scansServiceMock.enqueue).toHaveBeenCalledWith(
        expect.objectContaining({
          assetId: 'asset-1',
          batchId: 'batch-1',
          stage: 1,
          type: ScanType.SUBDOMAIN_DISCOVERY,
        }),
      );
      expect(workerMock.kick).toHaveBeenCalled();
      expect(res.id).toBe('batch-1');
    });
  });

  describe('advancePipeline', () => {
    it('no avanza la etapa si hay escaneos pendientes o en ejecución', async () => {
      prismaMock.diagnosticBatch.findUnique.mockResolvedValue({
        id: 'batch-1',
        profile: DiagnosticProfile.COMMERCE_360,
        status: DiagnosticBatchStatus.IN_PROGRESS,
        currentStage: 1,
        totalStages: 3,
        asset: { type: AssetType.DOMAIN },
        scans: [
          { stage: 1, status: ScanStatus.RUNNING },
        ],
      });

      await service.advancePipeline('batch-1');

      expect(prismaMock.diagnosticBatch.update).not.toHaveBeenCalled();
      expect(scansServiceMock.enqueue).not.toHaveBeenCalled();
    });

    it('avanza a la siguiente etapa cuando todos los escaneos de la etapa actual terminan', async () => {
      prismaMock.diagnosticBatch.findUnique.mockResolvedValue({
        id: 'batch-1',
        profile: DiagnosticProfile.COMMERCE_360,
        status: DiagnosticBatchStatus.IN_PROGRESS,
        currentStage: 1,
        totalStages: 3,
        assetId: 'asset-1',
        organizationId: 'org-1',
        asset: { type: AssetType.DOMAIN },
        scans: [
          { stage: 1, status: ScanStatus.COMPLETED },
        ],
      });

      await service.advancePipeline('batch-1');

      expect(prismaMock.diagnosticBatch.update).toHaveBeenCalledWith({
        where: { id: 'batch-1' },
        data: { currentStage: 2 },
      });
      expect(scansServiceMock.enqueue).toHaveBeenCalledWith(
        expect.objectContaining({
          batchId: 'batch-1',
          stage: 2,
          type: ScanType.PORT_SCAN,
        }),
      );
    });

    it('completa el lote y calcula resumen de postura cuando termina la última etapa', async () => {
      prismaMock.diagnosticBatch.findUnique.mockResolvedValue({
        id: 'batch-1',
        profile: DiagnosticProfile.COMMERCE_360,
        status: DiagnosticBatchStatus.IN_PROGRESS,
        currentStage: 3,
        totalStages: 3,
        assetId: 'asset-1',
        organizationId: 'org-1',
        asset: { type: AssetType.DOMAIN },
        scans: [
          { stage: 1, status: ScanStatus.COMPLETED, ports: [] },
          { stage: 2, status: ScanStatus.COMPLETED, ports: [{ port: 443, state: 'open' }] },
          { stage: 3, status: ScanStatus.COMPLETED, type: ScanType.WEB_HEADERS, ports: [], summary: { waf: 'Cloudflare', technologies: [{ name: 'WordPress' }] } },
        ],
      });

      prismaMock.riskScore.findFirst.mockResolvedValue({ score: 85, grade: 'B' });
      prismaMock.finding.findMany.mockResolvedValue([
        { id: 'f-1', fingerprint: 'fp-1', severity: 'HIGH', status: 'OPEN', title: 'SRI Missing' },
      ]);
      prismaMock.discoveredHost.count.mockResolvedValue(4);

      await service.advancePipeline('batch-1');

      expect(prismaMock.diagnosticBatch.update).toHaveBeenCalledWith({
        where: { id: 'batch-1' },
        data: expect.objectContaining({
          status: DiagnosticBatchStatus.COMPLETED,
          summary: expect.objectContaining({
            score: { score: 85, grade: 'B' },
            findingsCount: expect.objectContaining({ total: 1, high: 1 }),
            surface: expect.objectContaining({
              openPorts: [443],
              waf: 'Cloudflare',
              technologies: ['WordPress'],
            }),
          }),
        }),
      });
    });
  });

  describe('getPostureDiff', () => {
    it('compara dos diagnósticos y detecta mejoras, hallazgos remediados y regresiones', async () => {
      const fromBatch = {
        id: 'batch-initial',
        finishedAt: new Date('2026-10-01'),
        summary: {
          score: { score: 70, grade: 'C' },
          findingSnapshots: [
            { fingerprint: 'fp-vuln-1', ruleId: 'WEB-SRI-MISSING-EXTERNAL-SCRIPT', title: 'SRI Falta', severity: 'HIGH', status: 'OPEN' },
            { fingerprint: 'fp-vuln-2', ruleId: 'HDR-CSP-MISSING', title: 'CSP Missing', severity: 'MEDIUM', status: 'OPEN' },
          ],
          surface: { openPorts: [80, 443], subdomainsCount: 2, waf: 'Ninguno detectado' },
        },
      };

      const toBatch = {
        id: 'batch-current',
        finishedAt: new Date('2026-10-22'),
        summary: {
          score: { score: 88, grade: 'B' },
          findingSnapshots: [
            // fp-vuln-1 fue resuelta (ya no está)
            // fp-vuln-2 persiste
            { fingerprint: 'fp-vuln-2', ruleId: 'HDR-CSP-MISSING', title: 'CSP Missing', severity: 'MEDIUM', status: 'OPEN' },
            // fp-vuln-3 es nueva regresión
            { fingerprint: 'fp-vuln-3', ruleId: 'PATH-SOURCEMAP-EXPOSED', title: 'SourceMap Expuesto', severity: 'LOW', status: 'OPEN' },
          ],
          surface: { openPorts: [443], subdomainsCount: 3, waf: 'Cloudflare' },
        },
      };

      jest.spyOn(service, 'getBatch')
        .mockResolvedValueOnce(toBatch as any)
        .mockResolvedValueOnce(fromBatch as any);

      const diff = await service.getPostureDiff('org-1', 'asset-1', 'batch-initial', 'batch-current');

      expect(diff.score.previous).toBe(70);
      expect(diff.score.current).toBe(88);
      expect(diff.score.delta).toBe(18);
      expect(diff.score.gradeChange).toBe('IMPROVED');

      expect(diff.findings.remediatedCount).toBe(1);
      expect(diff.findings.remediatedFindings[0].fingerprint).toBe('fp-vuln-1');

      expect(diff.findings.newCount).toBe(1);
      expect(diff.findings.newFindings[0].fingerprint).toBe('fp-vuln-3');

      expect(diff.findings.persistentCount).toBe(1);
      expect(diff.findings.persistentFindings[0].fingerprint).toBe('fp-vuln-2');

      expect(diff.surface.closedPorts).toEqual([80]);
      expect(diff.surface.wafChanged).toBe(true);
      expect(diff.assessment).toContain('mejoró +18 puntos');
    });
  });

  describe('cancelBatch', () => {
    it('cancela escaneos activos y marca el lote como CANCELLED', async () => {
      prismaMock.diagnosticBatch.findFirst.mockResolvedValue({
        id: 'batch-1',
        scans: [
          { id: 'scan-1', status: ScanStatus.RUNNING },
          { id: 'scan-2', status: ScanStatus.PENDING },
        ],
      });

      const res = await service.cancelBatch('org-1', 'batch-1');

      expect(scansServiceMock.cancel).toHaveBeenCalledTimes(2);
      expect(prismaMock.diagnosticBatch.update).toHaveBeenCalledWith({
        where: { id: 'batch-1' },
        data: expect.objectContaining({ status: DiagnosticBatchStatus.CANCELLED }),
      });
      expect(res.batchId).toBe('batch-1');
    });
  });
});
