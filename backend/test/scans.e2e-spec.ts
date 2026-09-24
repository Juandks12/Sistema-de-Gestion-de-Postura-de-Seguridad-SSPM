import { INestApplication, ValidationPipe } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import request from 'supertest';
import { AppModule } from '../src/app.module';
import { PrismaClientExceptionFilter } from '../src/common/filters/prisma-exception.filter';
import { PrismaService } from '../src/prisma/prisma.service';
import { NmapRunner } from '../src/scans/nmap/nmap.runner';
import { NmapRunOutput } from '../src/scans/nmap/nmap.types';

const FIXTURE = readFileSync(
  join(__dirname, '..', 'src', 'scans', 'nmap', '__fixtures__', 'localhost-scan.xml'),
  'utf8',
);

/** Sustituto de Nmap: devuelve el fixture, falla o se queda "colgado" hasta cancelarse. */
class FakeNmapRunner {
  mode: 'ok' | 'hang' | 'fail' = 'ok';
  readonly calls: string[][] = [];
  private readonly hanging = new Map<string, (out: NmapRunOutput) => void>();

  async run(scanId: string, args: string[]): Promise<NmapRunOutput> {
    this.calls.push(args);
    const base = { stderr: '', timedOut: false, cancelled: false, durationMs: 1234 };
    if (this.mode === 'fail') {
      return { ...base, stdout: '', stderr: 'QUITTING! simulated failure', exitCode: 1 };
    }
    if (this.mode === 'hang') {
      return new Promise((resolve) => this.hanging.set(scanId, resolve));
    }
    return { ...base, stdout: FIXTURE, exitCode: 0 };
  }

  cancel(scanId: string): boolean {
    const resolve = this.hanging.get(scanId);
    if (!resolve) return false;
    this.hanging.delete(scanId);
    resolve({ stdout: '', stderr: '', exitCode: null, timedOut: false, cancelled: true, durationMs: 1 });
    return true;
  }

  cancelAll(): string[] {
    const ids = [...this.hanging.keys()];
    ids.forEach((id) => this.cancel(id));
    return ids;
  }

  get runningCount(): number {
    return this.hanging.size;
  }
}

describe('Scans (e2e) - RF-02/RF-03 con Nmap', () => {
  let app: INestApplication;
  let prisma: PrismaService;
  const fake = new FakeNmapRunner();
  const suffix = Date.now();
  const orgIds: string[] = [];

  let tokenAdminA: string;
  let tokenViewerA: string;
  let tokenAdminB: string;
  let assetId: string;
  let completedScanId: string;

  const http = () => request(app.getHttpServer());

  const register = async (org: string, email: string) => {
    const res = await http()
      .post('/api/v1/auth/register')
      .send({ organizationName: org, fullName: 'Test', email, password: 'Password123' })
      .expect(201);
    orgIds.push(res.body.user.organizationId);
    return res.body.accessToken as string;
  };

  const waitForStatus = async (scanId: string, statuses: string[], token = tokenAdminA) => {
    const deadline = Date.now() + 10000;
    for (;;) {
      const res = await http()
        .get(`/api/v1/scans/${scanId}`)
        .set('Authorization', `Bearer ${token}`)
        .expect(200);
      if (statuses.includes(res.body.status)) return res.body;
      if (Date.now() > deadline) {
        throw new Error(`El escaneo sigue en ${res.body.status}; se esperaba ${statuses.join('/')}`);
      }
      await new Promise((r) => setTimeout(r, 100));
    }
  };

  const requestScan = (token: string, id = assetId, body: object = {}) =>
    http().post(`/api/v1/assets/${id}/scans`).set('Authorization', `Bearer ${token}`).send(body);

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({ imports: [AppModule] })
      .overrideProvider(NmapRunner)
      .useValue(fake)
      .compile();
    app = moduleRef.createNestApplication();
    app.setGlobalPrefix('api/v1');
    app.useGlobalPipes(
      new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true }),
    );
    app.useGlobalFilters(new PrismaClientExceptionFilter());
    app.enableShutdownHooks();
    await app.init();
    prisma = app.get(PrismaService);

    tokenAdminA = await register(`Scan Org A ${suffix}`, `scan-a-${suffix}@test.local`);
    tokenAdminB = await register(`Scan Org B ${suffix}`, `scan-b-${suffix}@test.local`);

    await http()
      .post('/api/v1/users')
      .set('Authorization', `Bearer ${tokenAdminA}`)
      .send({ fullName: 'Viewer', email: `scan-v-${suffix}@test.local`, password: 'Password123', role: 'VIEWER' })
      .expect(201);
    tokenViewerA = (
      await http()
        .post('/api/v1/auth/login')
        .send({ email: `scan-v-${suffix}@test.local`, password: 'Password123' })
        .expect(200)
    ).body.accessToken;

    assetId = (
      await http()
        .post('/api/v1/assets')
        .set('Authorization', `Bearer ${tokenAdminA}`)
        .send({ value: '45.33.32.156', name: 'scanme', authorizationConfirmed: true })
        .expect(201)
    ).body.id;
  });

  afterAll(async () => {
    fake.cancelAll();
    await prisma.organization.deleteMany({ where: { id: { in: orgIds } } });
    await app.close();
  });

  it('VIEWER no puede lanzar escaneos (403)', async () => {
    await requestScan(tokenViewerA).expect(403);
  });

  it('otra organización no puede escanear el activo (404)', async () => {
    await requestScan(tokenAdminB).expect(404);
  });

  it('rechaza tipos de escaneo aún no implementados (400)', async () => {
    await requestScan(tokenAdminA, assetId, { type: 'SSL_CERT' }).expect(400);
  });

  it('encola el escaneo (202), lo ejecuta de forma asíncrona y guarda puertos y servicios', async () => {
    fake.mode = 'ok';
    const res = await requestScan(tokenAdminA).expect(202);
    expect(res.body.status).toBe('PENDING');
    completedScanId = res.body.id;

    const scan = await waitForStatus(completedScanId, ['COMPLETED', 'FAILED']);
    expect(scan.status).toBe('COMPLETED');
    expect(scan.targetAddress).toBe('45.33.32.156');
    expect(scan.startedAt).toBeTruthy();
    expect(scan.finishedAt).toBeTruthy();
    expect(scan.summary).toMatchObject({ openPortsCount: 2, hostStatus: 'up', nmapVersion: '7.94SVN' });
    expect(scan.ports).toHaveLength(4);
    expect(scan.ports).toContainEqual(
      expect.objectContaining({
        port: 5432,
        protocol: 'tcp',
        state: 'open',
        serviceName: 'postgresql',
        product: 'PostgreSQL DB',
        version: '9.6.0 or later',
        cpe: ['cpe:/a:postgresql:postgresql'],
      }),
    );
    expect(scan.parameters.args.slice(-1)).toEqual(['45.33.32.156']);
    expect(scan.rawResult).toBeUndefined();

    const lastArgs = fake.calls[fake.calls.length - 1];
    expect(lastArgs).toEqual(expect.arrayContaining(['-sV', '-oX', '-']));
  });

  it('expone la salida completa solo bajo demanda (includeRaw)', async () => {
    const res = await http()
      .get(`/api/v1/scans/${completedScanId}?includeRaw=true`)
      .set('Authorization', `Bearer ${tokenViewerA}`)
      .expect(200);
    expect(res.body.rawResult.hosts[0].ports).toHaveLength(4);
  });

  it('actualiza el activo y calcula la superficie expuesta actual', async () => {
    const asset = await http()
      .get(`/api/v1/assets/${assetId}`)
      .set('Authorization', `Bearer ${tokenAdminA}`)
      .expect(200);
    expect(asset.body.lastScannedAt).toBeTruthy();

    const exposure = await http()
      .get(`/api/v1/assets/${assetId}/exposure`)
      .set('Authorization', `Bearer ${tokenViewerA}`)
      .expect(200);
    expect(exposure.body.scan.id).toBe(completedScanId);
    expect(exposure.body.openPorts.map((p: { port: number }) => p.port)).toEqual([5432, 8089]);
  });

  it('impide duplicados en curso (409) y permite cancelar un escaneo en ejecución', async () => {
    fake.mode = 'hang';
    const { body } = await requestScan(tokenAdminA).expect(202);
    await waitForStatus(body.id, ['RUNNING']);

    await requestScan(tokenAdminA).expect(409);

    const cancelled = await http()
      .post(`/api/v1/scans/${body.id}/cancel`)
      .set('Authorization', `Bearer ${tokenAdminA}`)
      .expect(200);
    expect(cancelled.body.status).toBe('CANCELLED');

    await http()
      .post(`/api/v1/scans/${body.id}/cancel`)
      .set('Authorization', `Bearer ${tokenAdminA}`)
      .expect(409);

    // El worker no debe sobrescribir el estado cancelado.
    await new Promise((r) => setTimeout(r, 300));
    const after = await waitForStatus(body.id, ['CANCELLED']);
    expect(after.ports).toHaveLength(0);
  });

  it('registra el error cuando Nmap falla', async () => {
    fake.mode = 'fail';
    const { body } = await requestScan(tokenAdminA).expect(202);
    const scan = await waitForStatus(body.id, ['FAILED', 'COMPLETED']);
    expect(scan.status).toBe('FAILED');
    expect(scan.errorMessage).toMatch(/código 1/);
  });

  it('no permite escanear activos inactivos (400)', async () => {
    await http()
      .patch(`/api/v1/assets/${assetId}`)
      .set('Authorization', `Bearer ${tokenAdminA}`)
      .send({ isActive: false })
      .expect(200);
    await requestScan(tokenAdminA).expect(400);
  });

  it('aísla los escaneos por organización', async () => {
    const list = await http()
      .get('/api/v1/scans')
      .set('Authorization', `Bearer ${tokenAdminB}`)
      .expect(200);
    expect(list.body.meta.total).toBe(0);

    await http()
      .get(`/api/v1/scans/${completedScanId}`)
      .set('Authorization', `Bearer ${tokenAdminB}`)
      .expect(404);
    await http()
      .post(`/api/v1/scans/${completedScanId}/cancel`)
      .set('Authorization', `Bearer ${tokenAdminB}`)
      .expect(404);
    await http()
      .get(`/api/v1/assets/${assetId}/exposure`)
      .set('Authorization', `Bearer ${tokenAdminB}`)
      .expect(404);

    const own = await http()
      .get(`/api/v1/scans?assetId=${assetId}`)
      .set('Authorization', `Bearer ${tokenViewerA}`)
      .expect(200);
    expect(own.body.meta.total).toBe(3);
  });
});
