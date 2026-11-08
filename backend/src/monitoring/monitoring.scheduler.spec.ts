import { ConfigService } from '@nestjs/config';
import { CloudAccountStatus, MonitoringFrequency } from '@prisma/client';
import { AlertsService } from '../alerts/alerts.service';
import { CloudScanService } from '../cloud/cloud-scan.service';
import { PrismaService } from '../prisma/prisma.service';
import { RetentionService } from '../retention/retention.service';
import { DiagnosticOrchestratorService } from '../scans/diagnostic-orchestrator.service';
import { ScansService } from '../scans/scans.service';
import { MonitoringScheduler, nextRunAt, SCHEDULE_SLACK_MS } from './monitoring.scheduler';

describe('nextRunAt', () => {
  const now = new Date('2026-09-26T12:00:00Z');
  const day = 24 * 60 * 60 * 1000;

  it('sin monitoreo no hay próxima ejecución', () => {
    expect(nextRunAt(now, MonitoringFrequency.OFF, now)).toBeNull();
  });

  it('un activo nunca auditado por el monitoreo está vencido ya', () => {
    expect(nextRunAt(null, MonitoringFrequency.DAILY, now)).toEqual(now);
  });

  it('suma el periodo menos el margen del planificador', () => {
    expect(nextRunAt(now, MonitoringFrequency.DAILY, now)!.getTime()).toBe(now.getTime() + day - SCHEDULE_SLACK_MS);
    expect(nextRunAt(now, MonitoringFrequency.WEEKLY, now)!.getTime()).toBe(now.getTime() + 7 * day - SCHEDULE_SLACK_MS);
  });
});

describe('MonitoringScheduler.runOnce', () => {
  let scheduler: MonitoringScheduler;
  let prismaMock: {
    asset: { findMany: jest.Mock; updateMany: jest.Mock };
    cloudAccount: { findMany: jest.Mock; updateMany: jest.Mock };
  };
  let configMock: { get: jest.Mock };
  let scansMock: { enqueueAll: jest.Mock };
  let alertsMock: { retryFailedDeliveries: jest.Mock };
  let retentionMock: { runRetention: jest.Mock };
  let diagnosticOrchestratorMock: { startScheduledBatch: jest.Mock };
  let cloudScanMock: { runAccountAudit: jest.Mock };

  beforeEach(() => {
    prismaMock = {
      asset: {
        findMany: jest.fn(),
        updateMany: jest.fn().mockResolvedValue({ count: 1 }),
      },
      cloudAccount: {
        findMany: jest.fn(),
        updateMany: jest.fn().mockResolvedValue({ count: 1 }),
      },
    };
    configMock = {
      get: jest.fn((key: string) => {
        if (key === 'SCHEDULER_BATCH_SIZE') return 10;
        if (key === 'ASSET_VERIFICATION_REQUIRED') return false;
        return undefined;
      }),
    };
    scansMock = {
      enqueueAll: jest.fn().mockResolvedValue({ queued: [{ id: 's-1' }] }),
    };
    alertsMock = {
      retryFailedDeliveries: jest.fn().mockResolvedValue({ deliveriesRetried: 0, succeeded: 0, failed: 0 }),
    };
    retentionMock = {
      runRetention: jest.fn().mockResolvedValue({}),
    };
    diagnosticOrchestratorMock = {
      startScheduledBatch: jest.fn().mockResolvedValue({
        batchId: 'batch-sched-1',
        queued: [{ id: 's-1' }, { id: 's-2' }, { id: 's-3' }, { id: 's-4' }],
        skipped: [],
      }),
    };
    cloudScanMock = {
      runAccountAudit: jest.fn().mockResolvedValue({
        stats: { activeFindings: 2 },
      }),
    };

    scheduler = new MonitoringScheduler(
      prismaMock as unknown as PrismaService,
      configMock as unknown as ConfigService,
      scansMock as unknown as ScansService,
      alertsMock as unknown as AlertsService,
      retentionMock as unknown as RetentionService,
      diagnosticOrchestratorMock as unknown as DiagnosticOrchestratorService,
      cloudScanMock as unknown as CloudScanService,
    );
  });

  it('inicia lotes 360° programados para activos perimetrales y re-audita cuentas Cloud conectadas', async () => {
    // DAILY: 1 activo vencido y 1 cuenta cloud conectada vencida; WEEKLY: 0
    prismaMock.asset.findMany
      .mockResolvedValueOnce([{ id: 'asset-domain-1', organizationId: 'org-1' }])
      .mockResolvedValueOnce([]);

    prismaMock.cloudAccount.findMany
      .mockResolvedValueOnce([{ id: 'cloud-aws-1', organizationId: 'org-1' }])
      .mockResolvedValueOnce([]);

    const now = new Date('2026-11-07T12:00:00Z');
    const res = await scheduler.runOnce(now);

    expect(res.dueAssets).toBe(1);
    expect(res.claimed).toBe(1);
    expect(res.queuedScans).toBe(4);
    expect(res.diagnosticBatchesStarted).toBe(1);
    expect(res.dueCloudAccounts).toBe(1);
    expect(res.auditedCloudAccounts).toBe(1);
    expect(res.errors).toBe(0);

    expect(diagnosticOrchestratorMock.startScheduledBatch).toHaveBeenCalledWith(
      'org-1',
      'asset-domain-1',
    );
    expect(cloudScanMock.runAccountAudit).toHaveBeenCalledWith('org-1', 'cloud-aws-1');
    expect(prismaMock.cloudAccount.findMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: expect.objectContaining({
          status: CloudAccountStatus.CONNECTED,
        }),
      }),
    );
  });

  it('omite activos o cuentas cloud ya reclamados por otra instancia concurrente', async () => {
    prismaMock.asset.findMany
      .mockResolvedValueOnce([{ id: 'asset-1', organizationId: 'org-1' }])
      .mockResolvedValueOnce([]);
    prismaMock.asset.updateMany.mockResolvedValueOnce({ count: 0 });

    prismaMock.cloudAccount.findMany
      .mockResolvedValueOnce([{ id: 'cloud-1', organizationId: 'org-1' }])
      .mockResolvedValueOnce([]);
    prismaMock.cloudAccount.updateMany.mockResolvedValueOnce({ count: 0 });

    const res = await scheduler.runOnce(new Date());

    expect(res.claimed).toBe(0);
    expect(res.auditedCloudAccounts).toBe(0);
    expect(diagnosticOrchestratorMock.startScheduledBatch).not.toHaveBeenCalled();
    expect(cloudScanMock.runAccountAudit).not.toHaveBeenCalled();
  });
});
