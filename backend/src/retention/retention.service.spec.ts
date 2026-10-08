import { ConfigService } from '@nestjs/config';
import { AuditService } from '../audit/audit.service';
import { AuthUser } from '../common/interfaces/auth-user.interface';
import { PrismaService } from '../prisma/prisma.service';
import { RetentionService } from './retention.service';

describe('RetentionService', () => {
  let service: RetentionService;
  let prismaMock: {
    scan: { findMany: jest.Mock; deleteMany: jest.Mock };
    scanPort: { count: jest.Mock };
    accountToken: { deleteMany: jest.Mock };
    loginAttempt: { deleteMany: jest.Mock };
    report: { deleteMany: jest.Mock };
    auditLog: { deleteMany: jest.Mock };
  };
  let configMock: { get: jest.Mock };
  let auditMock: { record: jest.Mock };

  const actor: AuthUser = {
    id: 'u-1',
    organizationId: 'org-1',
    role: 'ADMIN',
    fullName: 'Admin Test',
    email: 'admin@test.local',
  };

  beforeEach(() => {
    prismaMock = {
      scan: {
        findMany: jest.fn(),
        deleteMany: jest.fn(),
      },
      scanPort: {
        count: jest.fn(),
      },
      accountToken: {
        deleteMany: jest.fn(),
      },
      loginAttempt: {
        deleteMany: jest.fn(),
      },
      report: {
        deleteMany: jest.fn(),
      },
      auditLog: {
        deleteMany: jest.fn(),
      },
    };

    configMock = {
      get: jest.fn((key: string) => {
        const conf: Record<string, any> = {
          RETENTION_ENABLED: true,
          RETENTION_SCANS_DAYS: 90,
          RETENTION_AUDIT_DAYS: 365,
          RETENTION_TOKENS_DAYS: 30,
          RETENTION_REPORTS_DAYS: 180,
        };
        return conf[key];
      }),
    };

    auditMock = {
      record: jest.fn(),
    };

    service = new RetentionService(
      prismaMock as unknown as PrismaService,
      configMock as unknown as ConfigService,
      auditMock as unknown as AuditService,
    );
  });

  it('retorna el estado con los valores por defecto', () => {
    const status = service.getStatus();
    expect(status.enabled).toBe(true);
    expect(status.scansRetentionDays).toBe(90);
    expect(status.auditRetentionDays).toBe(365);
    expect(status.tokensRetentionDays).toBe(30);
    expect(status.reportsRetentionDays).toBe(180);
    expect(status.lastRunAt).toBeNull();
    expect(status.lastResult).toBeNull();
  });

  it('omite la purga si RETENTION_ENABLED=false', async () => {
    configMock.get.mockImplementation((key: string) => (key === 'RETENTION_ENABLED' ? false : 90));
    const result = await service.runRetention(actor);

    expect(result.scansPurged).toBe(0);
    expect(prismaMock.scan.deleteMany).not.toHaveBeenCalled();
    expect(prismaMock.auditLog.deleteMany).not.toHaveBeenCalled();
  });

  it('purga escaneos antiguos protegiendo el último de cada activo y borra tokens/auditorías expiradas', async () => {
    const now = new Date('2026-10-08T12:00:00Z');

    // Último escaneo por activo (protegido)
    prismaMock.scan.findMany
      .mockResolvedValueOnce([{ id: 'scan-protected-latest' }]) // distinct latest
      .mockResolvedValueOnce([
        { id: 'scan-old-1' },
        { id: 'scan-old-2' },
        { id: 'scan-protected-latest' },
      ]); // candidatos antiguos

    prismaMock.scanPort.count.mockResolvedValueOnce(5);
    prismaMock.scan.deleteMany.mockResolvedValueOnce({ count: 2 });
    prismaMock.accountToken.deleteMany.mockResolvedValueOnce({ count: 3 });
    prismaMock.loginAttempt.deleteMany.mockResolvedValueOnce({ count: 1 });
    prismaMock.report.deleteMany.mockResolvedValueOnce({ count: 4 });
    prismaMock.auditLog.deleteMany.mockResolvedValueOnce({ count: 10 });

    const result = await service.runRetention(actor, now);

    expect(result.scansPurged).toBe(2);
    expect(result.scanPortsPurged).toBe(5);
    expect(result.tokensPurged).toBe(3);
    expect(result.loginAttemptsPurged).toBe(1);
    expect(result.reportsPurged).toBe(4);
    expect(result.auditLogsPurged).toBe(10);
    expect(result.triggeredBy).toBe(actor.email);

    // Verifica que el scan protegido no se incluyó en la lista de borrado
    expect(prismaMock.scan.deleteMany).toHaveBeenCalledWith({
      where: { id: { in: ['scan-old-1', 'scan-old-2'] } },
    });

    // Auditoría registrada
    expect(auditMock.record).toHaveBeenCalledWith({
      organizationId: actor.organizationId,
      action: 'system.retention_cleanup',
      actor,
      target: expect.objectContaining({ type: 'system', id: 'retention' }),
      detail: expect.objectContaining({
        scansPurged: 2,
        tokensPurged: 3,
        auditLogsPurged: 10,
      }),
    });

    // getStatus ahora refleja la última ejecución
    const status = service.getStatus();
    expect(status.lastRunAt).toBe(now.toISOString());
    expect(status.lastResult).toEqual(result);
  });
});
