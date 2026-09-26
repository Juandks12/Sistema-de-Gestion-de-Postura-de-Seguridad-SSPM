import { INestApplication, ValidationPipe } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { readFileSync } from 'node:fs';
import * as http from 'node:http';
import { AddressInfo } from 'node:net';
import { join } from 'node:path';
import request from 'supertest';
import { AlertsService } from '../src/alerts/alerts.service';
import { PrismaClientExceptionFilter } from '../src/common/filters/prisma-exception.filter';
import { MonitoringScheduler } from '../src/monitoring/monitoring.scheduler';
import { PrismaService } from '../src/prisma/prisma.service';
import { NmapRunner } from '../src/scans/nmap/nmap.runner';
import { NmapRunOutput } from '../src/scans/nmap/nmap.types';
import { ScanWorkerService } from '../src/scans/scan-worker.service';

const FULL = readFileSync(join(__dirname, '..', 'src', 'scans', 'nmap', '__fixtures__', 'localhost-scan.xml'), 'utf8');
/** Mismo resultado sin el puerto 8089: sirve de línea base para detectar "puerto nuevo". */
const BASELINE = FULL.replace(/<port protocol="tcp" portid="8089">[\s\S]*?<\/port>/, '');

class FakeNmapRunner {
  output = BASELINE;
  async run(): Promise<NmapRunOutput> {
    return { stdout: this.output, stderr: '', exitCode: 0, timedOut: false, cancelled: false, durationMs: 50 };
  }
}

function binaryParser(res: request.Response, callback: (err: Error | null, body: Buffer) => void) {
  const chunks: Buffer[] = [];
  res.on('data', (c: Buffer) => chunks.push(c));
  res.on('end', () => callback(null, Buffer.concat(chunks)));
}

/**
 * Sprint 4: alertas (RF-10), canales de notificación, monitoreo continuo
 * (sección 10.4) y reportes PDF (RF-09).
 */
describe('Alertas, monitoreo y reportes (e2e)', () => {
  let app: INestApplication;
  let prisma: PrismaService;
  let hookServer: http.Server;
  let hookUrl: string;
  const received: Array<Record<string, unknown>> = [];
  const fake = new FakeNmapRunner();
  const suffix = Date.now();
  const orgIds: string[] = [];

  let admin: string;
  let viewer: string;
  let otherOrg: string;
  let assetId: string;
  let webhookChannelId: string;
  let emailChannelId: string;
  let alertId: string;

  const http_ = () => request(app.getHttpServer());
  const auth = (token: string) => ({ Authorization: `Bearer ${token}` });

  const register = async (org: string, email: string) => {
    const res = await http_()
      .post('/api/v1/auth/register')
      .send({ organizationName: org, fullName: 'Admin Test', email, password: 'Password123' })
      .expect(201);
    orgIds.push(res.body.user.organizationId);
    return res.body.accessToken as string;
  };

  const runPortScan = async () => {
    const res = await http_().post(`/api/v1/assets/${assetId}/scans`).set(auth(admin)).send({ type: 'PORT_SCAN' }).expect(202);
    const deadline = Date.now() + 15000;
    for (;;) {
      const scan = await http_().get(`/api/v1/scans/${res.body.id}`).set(auth(admin)).expect(200);
      if (['COMPLETED', 'FAILED', 'CANCELLED'].includes(scan.body.status)) return scan.body;
      if (Date.now() > deadline) throw new Error('El escaneo no terminó a tiempo');
      await new Promise((r) => setTimeout(r, 100));
    }
  };

  beforeAll(async () => {
    hookServer = http.createServer((req, res) => {
      let body = '';
      req.on('data', (c: Buffer) => (body += c.toString()));
      req.on('end', () => {
        received.push({ path: req.url, contentType: req.headers['content-type'], ...(JSON.parse(body) as Record<string, unknown>) });
        res.writeHead(204);
        res.end();
      });
    });
    await new Promise<void>((resolve) => hookServer.listen(0, '127.0.0.1', resolve));
    hookUrl = `http://127.0.0.1:${(hookServer.address() as AddressInfo).port}/hooks/sspm`;

    // Modo laboratorio para poder entregar el webhook a un servidor local.
    process.env.ALLOW_PRIVATE_TARGETS = 'true';
    process.env.APP_URL = 'https://sspm.test';
    const { AppModule } = await import('../src/app.module');
    const moduleRef = await Test.createTestingModule({ imports: [AppModule] }).overrideProvider(NmapRunner).useValue(fake).compile();
    app = moduleRef.createNestApplication();
    app.setGlobalPrefix('api/v1');
    app.useGlobalPipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true }));
    app.useGlobalFilters(new PrismaClientExceptionFilter());
    app.enableShutdownHooks();
    await app.init();
    prisma = app.get(PrismaService);

    admin = await register(`Alert Org ${suffix}`, `alert-${suffix}@test.local`);
    otherOrg = await register(`Alert Org B ${suffix}`, `alert-b-${suffix}@test.local`);
    await http_()
      .post('/api/v1/users')
      .set(auth(admin))
      .send({ fullName: 'Gerente', email: `alert-v-${suffix}@test.local`, password: 'Password123', role: 'VIEWER' })
      .expect(201);
    viewer = (
      await http_().post('/api/v1/auth/login').send({ email: `alert-v-${suffix}@test.local`, password: 'Password123' }).expect(200)
    ).body.accessToken;
    assetId = (
      await http_()
        .post('/api/v1/assets')
        .set(auth(admin))
        .send({ value: '45.33.32.156', name: 'Servidor web', authorizationConfirmed: true })
        .expect(201)
    ).body.id;
  });

  afterAll(async () => {
    await app.get(AlertsService).flush();
    await prisma.organization.deleteMany({ where: { id: { in: orgIds } } });
    await app.close();
    await new Promise<void>((resolve) => hookServer.close(() => resolve()));
  });

  describe('canales de notificación', () => {
    it('solo ADMIN los gestiona', async () => {
      await http_().get('/api/v1/alerts/channels').set(auth(viewer)).expect(403);
      await http_()
        .post('/api/v1/alerts/channels')
        .set(auth(viewer))
        .send({ type: 'WEBHOOK', name: 'x', target: hookUrl })
        .expect(403);
    });

    it('valida el destino según el tipo', async () => {
      const bad = await http_()
        .post('/api/v1/alerts/channels')
        .set(auth(admin))
        .send({ type: 'WEBHOOK', name: 'FTP', target: 'ftp://example.org/hook' })
        .expect(400);
      expect(bad.body.message).toContain('HTTPS');
      await http_()
        .post('/api/v1/alerts/channels')
        .set(auth(admin))
        .send({ type: 'EMAIL', name: 'Correo', target: 'ti@empresa.com, no-es-un-correo' })
        .expect(400);
    });

    it('crea un webhook (URL enmascarada en la respuesta) y un canal de correo', async () => {
      const hook = await http_()
        .post('/api/v1/alerts/channels')
        .set(auth(admin))
        .send({ type: 'WEBHOOK', name: 'Webhook SOC', target: hookUrl, minSeverity: 'MEDIUM' })
        .expect(201);
      webhookChannelId = hook.body.id;
      expect(hook.body.target).not.toContain('/hooks/sspm');
      expect(hook.body.target).toMatch(/…sspm$/);

      const email = await http_()
        .post('/api/v1/alerts/channels')
        .set(auth(admin))
        .send({ type: 'EMAIL', name: 'Equipo TI', target: 'TI@Empresa.com; seguridad@empresa.com' })
        .expect(201);
      emailChannelId = email.body.id;
      expect(email.body).toMatchObject({ target: 'ti@empresa.com, seguridad@empresa.com', minSeverity: 'HIGH' });

      const list = await http_().get('/api/v1/alerts/channels').set(auth(admin)).expect(200);
      expect(list.body.items).toHaveLength(2);
      expect(list.body.emailEnabled).toBe(false);
    });

    it('envía notificaciones de prueba', async () => {
      const hook = await http_().post(`/api/v1/alerts/channels/${webhookChannelId}/test`).set(auth(admin)).expect(200);
      expect(hook.body.status).toBe('SENT');
      expect(received.at(-1)).toMatchObject({ path: '/hooks/sspm', contentType: 'application/json', event: 'alert.test', source: 'sspm' });

      // Sin SMTP configurado el correo se omite y se informa el motivo.
      const email = await http_().post(`/api/v1/alerts/channels/${emailChannelId}/test`).set(auth(admin)).expect(200);
      expect(email.body).toMatchObject({ status: 'SKIPPED', error: expect.stringContaining('SMTP') });

      const list = await http_().get('/api/v1/alerts/channels').set(auth(admin)).expect(200);
      const byId = Object.fromEntries(list.body.items.map((c: { id: string; lastDeliveryStatus: string }) => [c.id, c.lastDeliveryStatus]));
      expect(byId[webhookChannelId]).toBe('SENT');
      expect(byId[emailChannelId]).toBe('SKIPPED');
    });
  });

  describe('alertas tempranas (RF-10)', () => {
    it('el primer escaneo de puertos es la línea base y no alerta', async () => {
      const scan = await runPortScan();
      expect(scan.status).toBe('COMPLETED');
      expect(scan.source).toBe('MANUAL');
      await app.get(AlertsService).flush();
      const alerts = await http_().get('/api/v1/alerts').set(auth(admin)).expect(200);
      expect(alerts.body.items).toHaveLength(0);
    });

    it('un puerto nuevo genera una alerta y se notifica por los canales que cumplen la severidad', async () => {
      fake.output = FULL;
      const before = received.length;
      await runPortScan();
      await app.get(AlertsService).flush();

      const alerts = await http_().get('/api/v1/alerts').set(auth(viewer)).expect(200);
      expect(alerts.body.items).toHaveLength(1);
      const alert = alerts.body.items[0];
      alertId = alert.id;
      expect(alert).toMatchObject({ type: 'NEW_OPEN_PORT', severity: 'MEDIUM', acknowledgedAt: null });
      expect(alert.title).toContain('tcp/8089');
      expect(alert.asset.id).toBe(assetId);
      // El correo exige severidad HIGH: solo se usa el webhook.
      expect(alert.deliveries).toEqual([expect.objectContaining({ channelId: webhookChannelId, status: 'SENT' })]);

      expect(received.length).toBe(before + 1);
      expect(received.at(-1)).toMatchObject({
        event: 'alert.created',
        alert: expect.objectContaining({ id: alertId, type: 'NEW_OPEN_PORT', url: `https://sspm.test/assets/${assetId}` }),
      });
    });

    it('repetir el mismo escaneo no vuelve a alertar', async () => {
      await runPortScan();
      await app.get(AlertsService).flush();
      const alerts = await http_().get('/api/v1/alerts').set(auth(admin)).expect(200);
      expect(alerts.body.meta.total).toBe(1);
    });

    it('resumen y revisión de alertas', async () => {
      const summary = await http_().get('/api/v1/alerts/summary').set(auth(viewer)).expect(200);
      expect(summary.body).toMatchObject({ unacknowledged: 1, bySeverity: expect.objectContaining({ MEDIUM: 1 }) });

      await http_().post(`/api/v1/alerts/${alertId}/acknowledge`).set(auth(viewer)).expect(403);
      const ack = await http_().post(`/api/v1/alerts/${alertId}/acknowledge`).set(auth(admin)).expect(200);
      expect(ack.body.acknowledgedAt).not.toBeNull();
      expect(ack.body.acknowledgedBy.email).toBe(`alert-${suffix}@test.local`);

      const pending = await http_().get('/api/v1/alerts?acknowledged=false').set(auth(admin)).expect(200);
      expect(pending.body.items).toHaveLength(0);
      const done = await http_().get('/api/v1/alerts?acknowledged=true').set(auth(admin)).expect(200);
      expect(done.body.items).toHaveLength(1);
      expect((await http_().get('/api/v1/alerts/summary').set(auth(admin)).expect(200)).body.unacknowledged).toBe(0);
    });

    it('otra organización no ve ni modifica alertas ni canales', async () => {
      const list = await http_().get('/api/v1/alerts').set(auth(otherOrg)).expect(200);
      expect(list.body.items).toHaveLength(0);
      await http_().post(`/api/v1/alerts/${alertId}/acknowledge`).set(auth(otherOrg)).expect(404);
      await http_().patch(`/api/v1/alerts/channels/${webhookChannelId}`).set(auth(otherOrg)).send({ isActive: false }).expect(404);
      await http_().post(`/api/v1/alerts/channels/${webhookChannelId}/test`).set(auth(otherOrg)).expect(404);
    });
  });

  describe('monitoreo continuo (sección 10.4)', () => {
    it('solo ADMIN cambia la frecuencia', async () => {
      const status = await http_().get('/api/v1/monitoring').set(auth(viewer)).expect(200);
      expect(status.body.frequency).toBe('OFF');
      await http_().patch('/api/v1/monitoring').set(auth(viewer)).send({ frequency: 'DAILY' }).expect(403);
      await http_().patch('/api/v1/monitoring').set(auth(admin)).send({ frequency: 'HOURLY' }).expect(400);

      const updated = await http_().patch('/api/v1/monitoring').set(auth(admin)).send({ frequency: 'DAILY' }).expect(200);
      expect(updated.body).toMatchObject({ frequency: 'DAILY', periodHours: 24 });
      expect(updated.body.assets[0]).toMatchObject({ id: assetId, monitored: true, lastScheduledScanAt: null });
    });

    it('el planificador encola la auditoría completa una vez por periodo', async () => {
      const worker = app.get(ScanWorkerService);
      const kick = jest.spyOn(worker, 'kick').mockImplementation(() => undefined);
      try {
        const scheduler = app.get(MonitoringScheduler);
        const first = await scheduler.runOnce();
        expect(first.claimed).toBeGreaterThanOrEqual(1);

        const scans = await http_().get(`/api/v1/scans?assetId=${assetId}&status=PENDING`).set(auth(admin)).expect(200);
        const scheduled = scans.body.items.filter((s: { source: string }) => s.source === 'SCHEDULED');
        expect(scheduled.map((s: { type: string }) => s.type).sort()).toEqual(['PORT_SCAN', 'SENSITIVE_PATHS', 'SSL_CERT', 'WEB_HEADERS']);
        expect(scheduled.every((s: { requestedBy: unknown }) => s.requestedBy === null)).toBe(true);

        // Ya no está vencido: una segunda pasada no vuelve a encolarlo.
        const second = await scheduler.runOnce();
        const again = await http_().get(`/api/v1/scans?assetId=${assetId}&status=PENDING`).set(auth(admin)).expect(200);
        expect(again.body.items).toHaveLength(scheduled.length);
        expect(second.claimed).toBe(0);

        const status = await http_().get('/api/v1/monitoring').set(auth(admin)).expect(200);
        const next = new Date(status.body.assets[0].nextRunAt).getTime();
        expect(next).toBeGreaterThan(Date.now() + 23 * 3600 * 1000);

        for (const s of scheduled) {
          await http_().post(`/api/v1/scans/${s.id}/cancel`).set(auth(admin)).expect(200);
        }
      } finally {
        kick.mockRestore();
      }
    });
  });

  describe('reportes PDF (RF-09)', () => {
    it('la gerencia (VIEWER) descarga el reporte ejecutivo', async () => {
      const res = await http_().get('/api/v1/reports/executive').set(auth(viewer)).buffer(true).parse(binaryParser).expect(200);
      expect(res.headers['content-type']).toContain('application/pdf');
      expect(res.headers['content-disposition']).toMatch(/attachment; filename="sspm-reporte-ejecutivo-alert-org-\d+-\d{8}\.pdf"/);
      expect((res.body as Buffer).subarray(0, 5).toString()).toBe('%PDF-');
    });

    it('genera el reporte técnico de un activo', async () => {
      const res = await http_()
        .get(`/api/v1/reports/technical?assetId=${assetId}`)
        .set(auth(admin))
        .buffer(true)
        .parse(binaryParser)
        .expect(200);
      expect(res.headers['content-disposition']).toContain('sspm-reporte-tecnico-45-33-32-156-');
      expect((res.body as Buffer).length).toBeGreaterThan(2000);
    });

    it('no genera reportes de activos de otra organización', async () => {
      await http_().get(`/api/v1/reports/technical?assetId=${assetId}`).set(auth(otherOrg)).expect(404);
      await http_().get('/api/v1/reports/executive?assetId=no-es-uuid').set(auth(admin)).expect(400);
    });

    it('registra cada reporte generado', async () => {
      const res = await http_().get('/api/v1/reports').set(auth(viewer)).expect(200);
      expect(res.body.items).toHaveLength(2);
      expect(res.body.items[0]).toMatchObject({ type: 'TECHNICAL', asset: { id: assetId } });
      expect(res.body.items[1]).toMatchObject({ type: 'EXECUTIVE', asset: null, generatedBy: { fullName: 'Gerente' } });
      expect(res.body.items[1].pages).toBeGreaterThanOrEqual(2);
    });
  });
});
