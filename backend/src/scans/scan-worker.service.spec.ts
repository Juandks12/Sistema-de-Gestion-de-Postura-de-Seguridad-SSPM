import { ConfigService } from '@nestjs/config';
import { AssetType, ScanStatus, ScanType } from '@prisma/client';
import { AlertsService } from '../alerts/alerts.service';
import { DiscoveryService } from '../discovery/discovery.service';
import { FindingsService } from '../findings/findings.service';
import { PrismaService } from '../prisma/prisma.service';
import { RiskScoresService } from '../risk/risk-scores.service';
import { ScanCancellationService } from './scan-cancellation.service';
import { ScanExecutionError } from './scan.errors';
import { Scanner } from './scanner.interface';
import { ScanWorkerService } from './scan-worker.service';

describe('ScanWorkerService', () => {
  let service: ScanWorkerService;
  let prisma: jest.Mocked<PrismaService>;
  let config: jest.Mocked<ConfigService>;
  let cancellation: jest.Mocked<ScanCancellationService>;
  let findings: jest.Mocked<FindingsService>;
  let riskScores: jest.Mocked<RiskScoresService>;
  let alerts: jest.Mocked<AlertsService>;
  let discovery: jest.Mocked<DiscoveryService>;
  let mockScanner: Scanner;

  beforeEach(() => {
    prisma = {
      $queryRaw: jest.fn(),
      $transaction: jest.fn(),
      scan: {
        findUnique: jest.fn(),
        update: jest.fn(),
        updateMany: jest.fn(),
        findFirst: jest.fn(),
      },
      asset: {
        update: jest.fn(),
      },
      scanPort: {
        createMany: jest.fn(),
      },
    } as unknown as jest.Mocked<PrismaService>;

    config = {
      get: jest.fn().mockImplementation((key: string) => {
        if (key === 'SCAN_MAX_CONCURRENCY') return 2;
        if (key === 'SCAN_MAX_ADAPTIVE_CONCURRENCY') return 4;
        if (key === 'SCAN_MAX_CONCURRENCY_PER_ORG') return 1;
        if (key === 'SCAN_TIMEOUT_SECONDS') return 60;
        if (key === 'SCAN_WORKER_ENABLED') return true;
        if (key === 'SCAN_MAX_TRANSIENT_RETRIES') return 1;
        return undefined;
      }),
    } as unknown as jest.Mocked<ConfigService>;

    cancellation = {
      register: jest.fn().mockReturnValue(new AbortController().signal),
      release: jest.fn(),
      abortAll: jest.fn().mockReturnValue([]),
    } as unknown as jest.Mocked<ScanCancellationService>;

    findings = {
      syncForScan: jest.fn(),
    } as unknown as jest.Mocked<FindingsService>;

    riskScores = {
      snapshot: jest.fn(),
    } as unknown as jest.Mocked<RiskScoresService>;

    alerts = {
      handleScanCompleted: jest.fn(),
    } as unknown as jest.Mocked<AlertsService>;

    discovery = {
      syncForScan: jest.fn(),
    } as unknown as jest.Mocked<DiscoveryService>;

    mockScanner = {
      type: ScanType.PORT_SCAN,
      passive: false,
      run: jest.fn(),
    };

    service = new ScanWorkerService(
      prisma,
      config,
      cancellation,
      findings,
      riskScores,
      alerts,
      discovery,
      [mockScanner],
    );
  });

  describe('Concurrencia adaptativa', () => {
    it('inicia con la concurrencia base configurada', () => {
      expect(service.baseConcurrency).toBe(2);
      expect(service.maxAdaptiveConcurrency).toBe(4);
      expect(service.effectiveConcurrency).toBe(2);
    });

    it('escala hacia arriba tras 3 éxitos consecutivos hasta el límite adaptativo', () => {
      expect(service.effectiveConcurrency).toBe(2);

      service.adaptConcurrency(true);
      service.adaptConcurrency(true);
      expect(service.effectiveConcurrency).toBe(2);

      service.adaptConcurrency(true);
      expect(service.effectiveConcurrency).toBe(3);

      // Otros 3 éxitos consecutivos escalan a 4
      service.adaptConcurrency(true);
      service.adaptConcurrency(true);
      service.adaptConcurrency(true);
      expect(service.effectiveConcurrency).toBe(4);

      // No supera el máximo permitido
      service.adaptConcurrency(true);
      service.adaptConcurrency(true);
      service.adaptConcurrency(true);
      expect(service.effectiveConcurrency).toBe(4);
    });

    it('escala hacia abajo ante fallos consecutivos hasta el mínimo base', () => {
      // Subir primero a 3
      service.adaptConcurrency(true);
      service.adaptConcurrency(true);
      service.adaptConcurrency(true);
      expect(service.effectiveConcurrency).toBe(3);

      // Un fallo no reduce de inmediato
      service.adaptConcurrency(false);
      expect(service.effectiveConcurrency).toBe(3);

      // Segundo fallo consecutivo reduce a 2 (base)
      service.adaptConcurrency(false);
      expect(service.effectiveConcurrency).toBe(2);

      // No baja más allá de baseConcurrency
      service.adaptConcurrency(false);
      service.adaptConcurrency(false);
      expect(service.effectiveConcurrency).toBe(2);
    });
  });

  describe('Detección y reintento de fallos transitorios', () => {
    it('identifica correctamente errores de red transitorios', () => {
      expect(service.isTransientScanError(new Error('ETIMEDOUT: connection timed out'))).toBe(true);
      expect(service.isTransientScanError(new Error('read ECONNRESET'))).toBe(true);
      expect(service.isTransientScanError(new Error('socket hang up'))).toBe(true);
      expect(service.isTransientScanError(new Error('getaddrinfo EAI_AGAIN dns lookup failed'))).toBe(true);

      const errWithCode = Object.assign(new Error('Custom failure'), { code: 'ETIMEDOUT' });
      expect(service.isTransientScanError(errWithCode)).toBe(true);

      expect(service.isTransientScanError(new Error('La IP es privada o reservada; escaneo bloqueado'))).toBe(false);
      expect(service.isTransientScanError(new Error('El activo no existe'))).toBe(false);
    });

    it('reencola un escaneo fallido transitorio si no ha superado los reintentos', async () => {
      const scanId = 'scan-retry-1';
      const scanData = {
        id: scanId,
        type: ScanType.PORT_SCAN,
        organizationId: 'org-1',
        assetId: 'asset-1',
        parameters: { originalParam: 'test' },
        asset: {
          id: 'asset-1',
          value: '45.33.32.156',
          type: AssetType.IP,
          isActive: true,
          authorizationConfirmed: true,
          verifiedAt: new Date(),
        },
      };

      (prisma.scan.findUnique as jest.Mock).mockResolvedValue(scanData);
      (mockScanner.run as jest.Mock).mockRejectedValue(
        new ScanExecutionError('ETIMEDOUT: Connection timed out'),
      );

      type InternalWorker = {
        execute: (id: string) => Promise<void>;
        failStaleScans: () => Promise<void>;
      };
      const internal = service as unknown as InternalWorker;

      // Simular ejecución
      await internal.execute(scanId);

      // Debe haber actualizado el escaneo devolviéndolo a PENDING con parámetros de retry
      expect(prisma.scan.updateMany).toHaveBeenCalledWith({
        where: { id: scanId, status: ScanStatus.RUNNING },
        data: expect.objectContaining({
          status: ScanStatus.PENDING,
          startedAt: null,
          targetAddress: null,
          parameters: expect.objectContaining({
            originalParam: 'test',
            retryCount: 1,
            lastTransientError: expect.stringContaining('ETIMEDOUT'),
          }),
        }),
      });
    });

    it('marca como FAILED cuando los reintentos transitorios se agotan', async () => {
      const scanId = 'scan-retry-exhausted';
      const scanData = {
        id: scanId,
        type: ScanType.PORT_SCAN,
        organizationId: 'org-1',
        assetId: 'asset-1',
        parameters: { retryCount: 1 }, // Ya reintentó 1 vez (el máximo configurado es 1)
        asset: {
          id: 'asset-1',
          value: '45.33.32.156',
          type: AssetType.IP,
          isActive: true,
          authorizationConfirmed: true,
          verifiedAt: new Date(),
        },
      };

      (prisma.scan.findUnique as jest.Mock).mockResolvedValue(scanData);
      (mockScanner.run as jest.Mock).mockRejectedValue(
        new ScanExecutionError('ETIMEDOUT: Connection timed out'),
      );

      const internal = service as unknown as { execute: (id: string) => Promise<void> };
      await internal.execute(scanId);

      expect(prisma.scan.updateMany).toHaveBeenCalledWith({
        where: { id: scanId, status: ScanStatus.RUNNING },
        data: expect.objectContaining({
          status: ScanStatus.FAILED,
          errorMessage: expect.stringContaining('ETIMEDOUT'),
        }),
      });
    });
  });

  describe('failStaleScans', () => {
    it('marca como FAILED los escaneos RUNNING que superaron el tiempo de expiración', async () => {
      (prisma.scan.updateMany as jest.Mock).mockResolvedValue({ count: 2 });

      const internal = service as unknown as { failStaleScans: () => Promise<void> };
      await internal.failStaleScans();

      expect(prisma.scan.updateMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({
            status: ScanStatus.RUNNING,
          }),
          data: expect.objectContaining({
            status: ScanStatus.FAILED,
            errorMessage: expect.stringContaining('dejó de responder'),
          }),
        }),
      );
    });
  });

  describe('claimNext', () => {
    it('ejecuta la consulta con orden de pipeline y retorna el ID reclamado', async () => {
      (prisma.$queryRaw as jest.Mock).mockResolvedValueOnce([{ id: 'scan-pipeline-1' }]);

      const internal = service as unknown as { claimNext: () => Promise<string | null> };
      const claimedId = await internal.claimNext();

      expect(claimedId).toBe('scan-pipeline-1');
      expect(prisma.$queryRaw).toHaveBeenCalledTimes(1);

      // Verificar que el template string pasado a queryRaw contiene la lógica de priorización de pipeline
      const rawCall = (prisma.$queryRaw as jest.Mock).mock.calls[0];
      const queryStrings = rawCall[0] as string[];
      const fullSql = queryStrings.join(' ');
      expect(fullSql).toContain("WHEN 'PORT_SCAN' THEN 1");
      expect(fullSql).toContain("WHEN 'SUBDOMAIN_DISCOVERY' THEN 2");
      expect(fullSql).toContain("WHEN 'EMAIL_SECURITY' THEN 3");
      expect(fullSql).toContain("WHEN 'SSL_CERT' THEN 4");
      expect(fullSql).toContain("WHEN 'WEB_HEADERS' THEN 5");
      expect(fullSql).toContain("WHEN 'SENSITIVE_PATHS' THEN 6");
    });

    it('retorna null cuando no hay escaneos pendientes disponibles', async () => {
      (prisma.$queryRaw as jest.Mock).mockResolvedValueOnce([]);

      const internal = service as unknown as { claimNext: () => Promise<string | null> };
      const claimedId = await internal.claimNext();

      expect(claimedId).toBeNull();
    });
  });
});
