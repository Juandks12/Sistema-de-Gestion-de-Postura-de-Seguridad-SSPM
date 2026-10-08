import { ConfigService } from '@nestjs/config';
import { AlertChannelType, FindingSeverity, AlertType } from '@prisma/client';
import { AuditService } from '../audit/audit.service';
import { AuthUser } from '../common/interfaces/auth-user.interface';
import { PrismaService } from '../prisma/prisma.service';
import { AlertNotifierService, DeliveryResult } from './alert-notifier.service';
import { AlertsService, calculateNextRetry } from './alerts.service';

describe('AlertsService - Retry & Backoff', () => {
  describe('calculateNextRetry', () => {
    const baseMs = 60000; // 60s
    const now = new Date('2026-10-08T12:00:00.000Z');

    it('calcula backoff exponencial para el primer reintento (60s)', () => {
      const next = calculateNextRetry(1, 3, baseMs, now);
      expect(next).toBe(new Date('2026-10-08T12:01:00.000Z').toISOString());
    });

    it('calcula backoff exponencial para el segundo reintento (120s)', () => {
      const next = calculateNextRetry(2, 3, baseMs, now);
      expect(next).toBe(new Date('2026-10-08T12:02:00.000Z').toISOString());
    });

    it('retorna null cuando se alcanza el límite de reintentos (>= maxRetries)', () => {
      const next = calculateNextRetry(3, 3, baseMs, now);
      expect(next).toBeNull();
      expect(calculateNextRetry(4, 3, baseMs, now)).toBeNull();
    });
  });

  describe('retryFailedDeliveries and manual retry', () => {
    let service: AlertsService;
    let prismaMock: {
      alert: { findMany: jest.Mock; findUnique: jest.Mock; findFirst: jest.Mock; update: jest.Mock; create: jest.Mock };
      alertChannel: { findMany: jest.Mock; findFirst: jest.Mock; updateMany: jest.Mock };
      $transaction: jest.Mock;
    };
    let configMock: { get: jest.Mock };
    let notifierMock: { send: jest.Mock };
    let auditMock: { record: jest.Mock };

    const actor: AuthUser = {
      id: 'u-admin',
      organizationId: 'org-1',
      role: 'ADMIN',
      fullName: 'Admin Tester',
      email: 'admin@test.local',
    };

    beforeEach(() => {
      prismaMock = {
        alert: {
          findMany: jest.fn(),
          findUnique: jest.fn(),
          findFirst: jest.fn(),
          update: jest.fn(),
          create: jest.fn(),
        },
        alertChannel: {
          findMany: jest.fn(),
          findFirst: jest.fn(),
          updateMany: jest.fn().mockResolvedValue({ count: 1 }),
        },
        $transaction: jest.fn(),
      };

      configMock = {
        get: jest.fn((key: string) => {
          const map: Record<string, any> = {
            ALERT_MAX_RETRIES: 3,
            ALERT_RETRY_BASE_MS: 60000,
            APP_URL: 'http://localhost:8081',
            ALLOW_PRIVATE_TARGETS: false,
          };
          return map[key];
        }),
      };

      notifierMock = {
        send: jest.fn(),
      };

      auditMock = {
        record: jest.fn(),
      };

      service = new AlertsService(
        prismaMock as unknown as PrismaService,
        configMock as unknown as ConfigService,
        notifierMock as unknown as AlertNotifierService,
        auditMock as unknown as AuditService,
      );
    });

    it('retryFailedDeliveries reintenta entregas fallidas vencidas y actualiza a SENT tras éxito', async () => {
      const now = new Date('2026-10-08T12:05:00.000Z');
      const failedDelivery: DeliveryResult = {
        channelId: 'ch-1',
        channelType: AlertChannelType.WEBHOOK,
        channelName: 'Slack Webhook',
        status: 'FAILED',
        error: '503 Service Unavailable',
        at: '2026-10-08T12:00:00.000Z',
        attempts: 1,
        nextRetryAt: '2026-10-08T12:01:00.000Z', // vencido respecto a now (12:05)
      };

      const mockAlert = {
        id: 'alert-1',
        organizationId: 'org-1',
        type: AlertType.CRITICAL_FINDING,
        severity: FindingSeverity.CRITICAL,
        title: 'Certificado caducado',
        message: 'El certificado expiró',
        createdAt: new Date('2026-10-08T12:00:00.000Z'),
        deliveries: [failedDelivery],
        asset: { id: 'asset-1', value: 'example.com', name: 'Example' },
        organization: { name: 'Demo Org' },
      };

      prismaMock.alert.findMany.mockResolvedValueOnce([mockAlert]);
      prismaMock.alertChannel.findFirst.mockResolvedValueOnce({
        id: 'ch-1',
        type: AlertChannelType.WEBHOOK,
        name: 'Slack Webhook',
        target: 'https://example.com/webhook',
        signingSecret: null,
      });

      notifierMock.send.mockResolvedValueOnce({
        channelId: 'ch-1',
        channelType: AlertChannelType.WEBHOOK,
        channelName: 'Slack Webhook',
        status: 'SENT',
        detail: 'HTTP 200',
        at: now.toISOString(),
      });

      const summary = await service.retryFailedDeliveries(now);

      expect(summary.alertsChecked).toBe(1);
      expect(summary.deliveriesRetried).toBe(1);
      expect(summary.succeeded).toBe(1);
      expect(summary.failed).toBe(0);

      expect(prismaMock.alert.update).toHaveBeenCalledWith({
        where: { id: 'alert-1' },
        data: {
          deliveries: [
            expect.objectContaining({
              channelId: 'ch-1',
              status: 'SENT',
              attempts: 2,
              nextRetryAt: null,
            }),
          ],
        },
      });
    });

    it('manual retry reintenta bajo demanda y registra auditoria', async () => {
      const failedDelivery: DeliveryResult = {
        channelId: 'ch-1',
        channelType: AlertChannelType.WEBHOOK,
        channelName: 'Slack Webhook',
        status: 'FAILED',
        error: 'Timeout',
        at: '2026-10-08T12:00:00.000Z',
        attempts: 3, // ya había agotado reintentos automáticos
        nextRetryAt: null,
      };

      const mockAlert = {
        id: 'alert-1',
        organizationId: 'org-1',
        type: AlertType.CRITICAL_FINDING,
        severity: FindingSeverity.CRITICAL,
        title: 'CVE Explotado',
        message: 'CVE crítico encontrado',
        createdAt: new Date('2026-10-08T12:00:00.000Z'),
        deliveries: [failedDelivery],
        asset: { id: 'asset-1', value: 'example.com', name: 'Example' },
        organization: { name: 'Demo Org' },
      };

      prismaMock.alert.findFirst.mockResolvedValueOnce(mockAlert);
      prismaMock.alertChannel.findFirst.mockResolvedValueOnce({
        id: 'ch-1',
        type: AlertChannelType.WEBHOOK,
        name: 'Slack Webhook',
        target: 'https://example.com/webhook',
        signingSecret: null,
      });

      notifierMock.send.mockResolvedValueOnce({
        channelId: 'ch-1',
        channelType: AlertChannelType.WEBHOOK,
        channelName: 'Slack Webhook',
        status: 'SENT',
        detail: 'HTTP 200 OK',
        at: new Date().toISOString(),
      });

      prismaMock.alert.update.mockResolvedValueOnce({
        ...mockAlert,
        deliveries: [{ ...failedDelivery, status: 'SENT', attempts: 4, nextRetryAt: null }],
      });

      const updated = await service.retry(actor, 'alert-1', 'ch-1');

      expect(notifierMock.send).toHaveBeenCalled();
      expect(auditMock.record).toHaveBeenCalledWith({
        organizationId: actor.organizationId,
        action: 'alert.retry',
        actor,
        target: { type: 'alert', id: 'alert-1', label: 'CVE Explotado' },
        detail: {
          channelId: 'ch-1',
          retriedCount: 1,
        },
      });
      expect(updated).toBeDefined();
    });
  });
});
