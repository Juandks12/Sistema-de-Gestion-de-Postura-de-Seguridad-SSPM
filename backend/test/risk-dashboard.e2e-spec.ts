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

/** Nmap simulado: el fixture tiene PostgreSQL (HIGH) y un servidor HTTP (INFO) abiertos. */
class FakeNmapRunner {
  async run(): Promise<NmapRunOutput> {
    return { stdout: FIXTURE, stderr: '', exitCode: 0, timedOut: false, cancelled: false, durationMs: 100 };
  }
  get runningCount(): number {
    return 0;
  }
}

/**
 * Sprint 3: Security Score (RF-07), histórico de postura (RF-11) y dashboard.
 */
describe('Security Score y dashboard (e2e)', () => {
  let app: INestApplication;
  let prisma: PrismaService;
  const suffix = Date.now();
  const orgIds: string[] = [];
  let token: string;
  let viewerToken: string;
  let assetId: string;
  let secondAssetId: string;

  const http = () => request(app.getHttpServer());
  const auth = (t = token) => ({ Authorization: `Bearer ${t}` });

  const runPortScan = async (id: string) => {
    const res = await http().post(`/api/v1/assets/${id}/scans`).set(auth()).send({ type: 'PORT_SCAN' }).expect(202);
    const deadline = Date.now() + 15000;
    for (;;) {
      const scan = await http().get(`/api/v1/scans/${res.body.id}`).set(auth()).expect(200);
      if (['COMPLETED', 'FAILED'].includes(scan.body.status)) return scan.body;
      if (Date.now() > deadline) throw new Error('El escaneo no terminó a tiempo');
      await new Promise((r) => setTimeout(r, 100));
    }
  };

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({ imports: [AppModule] })
      .overrideProvider(NmapRunner)
      .useValue(new FakeNmapRunner())
      .compile();
    app = moduleRef.createNestApplication();
    app.setGlobalPrefix('api/v1');
    app.useGlobalPipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true }));
    app.useGlobalFilters(new PrismaClientExceptionFilter());
    app.enableShutdownHooks();
    await app.init();
    prisma = app.get(PrismaService);

    const reg = await http()
      .post('/api/v1/auth/register')
      .send({ organizationName: `Score Org ${suffix}`, fullName: 'Admin', email: `score-${suffix}@test.local`, password: 'Password123' })
      .expect(201);
    orgIds.push(reg.body.user.organizationId);
    token = reg.body.accessToken;

    await http()
      .post('/api/v1/users')
      .set(auth())
      .send({ fullName: 'Gerente', email: `score-v-${suffix}@test.local`, password: 'Password123', role: 'VIEWER' })
      .expect(201);
    viewerToken = (
      await http().post('/api/v1/auth/login').send({ email: `score-v-${suffix}@test.local`, password: 'Password123' }).expect(200)
    ).body.accessToken;

    assetId = (
      await http().post('/api/v1/assets').set(auth()).send({ value: '45.33.32.156', name: 'Servidor A', authorizationConfirmed: true }).expect(201)
    ).body.id;
    secondAssetId = (
      await http().post('/api/v1/assets').set(auth()).send({ value: '45.33.32.157', name: 'Servidor B', authorizationConfirmed: true }).expect(201)
    ).body.id;
  });

  afterAll(async () => {
    await prisma.organization.deleteMany({ where: { id: { in: orgIds } } });
    await app.close();
  });

  it('expone el modelo de puntuación', async () => {
    const res = await http().get('/api/v1/risk-scores/model').set(auth(viewerToken)).expect(200);
    expect(res.body.weights).toMatchObject({ CRITICAL: 25, HIGH: 10, MEDIUM: 4, LOW: 1, INFO: 0 });
    expect(res.body.grades.map((g: { grade: string }) => g.grade)).toEqual(['A', 'B', 'C', 'D', 'F']);
  });

  it('sin escaneos la organización y el activo están sin evaluar', async () => {
    const org = await http().get('/api/v1/risk-scores/current').set(auth()).expect(200);
    expect(org.body).toMatchObject({ scope: 'ORGANIZATION', score: null, grade: null, scoredAssets: 0, totalAssets: 2 });

    const asset = await http().get(`/api/v1/risk-scores/current?assetId=${assetId}`).set(auth()).expect(200);
    expect(asset.body).toMatchObject({ scope: 'ASSET', scored: false, score: null });

    const overview = await http().get('/api/v1/dashboard/overview').set(auth()).expect(200);
    expect(overview.body.securityScore.score).toBeNull();
    expect(overview.body.assets).toEqual({ total: 2, active: 2, inactive: 0 });
  });

  it('RF-07: un escaneo completado calcula el score y registra instantáneas', async () => {
    const scan = await runPortScan(assetId);
    expect(scan.status).toBe('COMPLETED');

    // Fixture: PostgreSQL expuesto (HIGH, -10) y HTTP abierto (INFO, 0) => 90 / A
    const asset = await http().get(`/api/v1/risk-scores/current?assetId=${assetId}`).set(auth()).expect(200);
    expect(asset.body).toMatchObject({ scored: true, score: 90, grade: 'A', counts: { HIGH: 1, INFO: 1 } });
    expect(asset.body.penalties.find((p: { severity: string }) => p.severity === 'HIGH').penalty).toBe(10);

    // Solo el activo escaneado cuenta para la organización.
    const org = await http().get('/api/v1/risk-scores/current').set(auth()).expect(200);
    expect(org.body).toMatchObject({ score: 90, grade: 'A', scoredAssets: 1, totalAssets: 2 });

    const history = await http().get(`/api/v1/risk-scores/history?assetId=${assetId}&granularity=raw`).set(auth()).expect(200);
    expect(history.body.points).toHaveLength(1);
    expect(history.body.points[0]).toMatchObject({ score: 90, grade: 'A', trigger: 'SCAN_COMPLETED', scanId: scan.id });
  });

  it('RF-08 → RF-07: aceptar un riesgo mejora el score y deja rastro en el histórico', async () => {
    const findings = await http().get(`/api/v1/findings?assetId=${assetId}&severity=HIGH&status=OPEN`).set(auth()).expect(200);
    const db = findings.body.items[0];
    expect(db.ruleId).toBe('SVC-DATABASE-EXPOSED');

    await http().patch(`/api/v1/findings/${db.id}`).set(auth()).send({ status: 'ACCEPTED', note: 'Filtrado por firewall' }).expect(200);

    const asset = await http().get(`/api/v1/risk-scores/current?assetId=${assetId}`).set(auth()).expect(200);
    expect(asset.body).toMatchObject({ score: 100, grade: 'A', counts: { HIGH: 0 } });

    const history = await http().get(`/api/v1/risk-scores/history?assetId=${assetId}&granularity=raw`).set(auth()).expect(200);
    expect(history.body.points.map((p: { trigger: string; score: number }) => [p.trigger, p.score])).toEqual([
      ['SCAN_COMPLETED', 90],
      ['FINDING_REVIEWED', 100],
    ]);

    // Reabrir el hallazgo vuelve a penalizar.
    await http().patch(`/api/v1/findings/${db.id}`).set(auth()).send({ status: 'OPEN' }).expect(200);
    const again = await http().get(`/api/v1/risk-scores/current?assetId=${assetId}`).set(auth()).expect(200);
    expect(again.body.score).toBe(90);
  });

  it('el score de la organización es la media de los activos evaluados', async () => {
    await runPortScan(secondAssetId);
    const org = await http().get('/api/v1/risk-scores/current').set(auth()).expect(200);
    expect(org.body).toMatchObject({ score: 90, scoredAssets: 2, counts: { HIGH: 2, INFO: 2 } });

    // Desactivar un activo lo excluye del cálculo y registra una instantánea ASSET_CHANGED.
    await http().patch(`/api/v1/assets/${secondAssetId}`).set(auth()).send({ isActive: false }).expect(200);
    const after = await http().get('/api/v1/risk-scores/current').set(auth()).expect(200);
    expect(after.body.scoredAssets).toBe(1);
    const history = await http().get('/api/v1/risk-scores/history?granularity=raw').set(auth()).expect(200);
    expect(history.body.points.at(-1).trigger).toBe('ASSET_CHANGED');
  });

  it('el dashboard resume score, hallazgos, activos y escaneos', async () => {
    const overview = await http().get('/api/v1/dashboard/overview').set(auth(viewerToken)).expect(200);
    expect(overview.body.securityScore).toMatchObject({ score: 90, grade: 'A', scoredAssets: 1, totalAssets: 1 });
    expect(overview.body.securityScore.trend.sincePrevious).toBeDefined();
    expect(overview.body.findings.open).toBeGreaterThanOrEqual(2);
    expect(overview.body.findings.byCategory.EXPOSED_SERVICE).toBeGreaterThanOrEqual(2);
    expect(overview.body.assets).toEqual({ total: 2, active: 1, inactive: 1 });
    expect(overview.body.scans.last7Days.COMPLETED).toBe(2);
    expect(overview.body.topFindings[0].severity).toBe('HIGH');
    expect(overview.body.recentScans).toHaveLength(2);

    const assets = await http().get('/api/v1/dashboard/assets').set(auth(viewerToken)).expect(200);
    expect(assets.body.total).toBe(2);
    expect(assets.body.items[0]).toMatchObject({ id: assetId, score: 90, grade: 'A', openFindings: 2 });
    expect(assets.body.items[0].lastScanByType.PORT_SCAN).toBeTruthy();

    const detail = await http().get(`/api/v1/dashboard/assets/${assetId}`).set(auth(viewerToken)).expect(200);
    expect(detail.body.securityScore.score).toBe(90);
    expect(detail.body.exposure.openPorts.map((p: { port: number }) => p.port)).toEqual([5432, 8089]);
    expect(detail.body.findings.open).toBe(2);
    expect(detail.body.history.length).toBeGreaterThanOrEqual(1);
    expect(detail.body.latestScans[0].type).toBe('PORT_SCAN');

    const history = await http().get('/api/v1/dashboard/history?days=7').set(auth(viewerToken)).expect(200);
    expect(history.body.days).toBe(7);
    expect(history.body.points.at(-1).score).toBe(90);
  });

  it('el recálculo manual está limitado por rol y registra instantáneas', async () => {
    await http().post('/api/v1/risk-scores/recalculate').set(auth(viewerToken)).expect(403);
    const res = await http().post('/api/v1/risk-scores/recalculate').set(auth()).expect(200);
    expect(res.body.organization).toMatchObject({ score: 90, trigger: 'MANUAL' });
    expect(res.body.assetSnapshots).toBe(1);
  });

  it('otra organización no ve scores, histórico ni dashboard ajenos', async () => {
    const other = await http()
      .post('/api/v1/auth/register')
      .send({ organizationName: `Score Org B ${suffix}`, fullName: 'Beto', email: `score-b-${suffix}@test.local`, password: 'Password123' })
      .expect(201);
    orgIds.push(other.body.user.organizationId);
    const t = other.body.accessToken;
    expect((await http().get('/api/v1/risk-scores/current').set(auth(t)).expect(200)).body.score).toBeNull();
    await http().get(`/api/v1/risk-scores/current?assetId=${assetId}`).set(auth(t)).expect(404);
    await http().get(`/api/v1/risk-scores/history?assetId=${assetId}`).set(auth(t)).expect(404);
    await http().get(`/api/v1/dashboard/assets/${assetId}`).set(auth(t)).expect(404);
    expect((await http().get('/api/v1/dashboard/overview').set(auth(t)).expect(200)).body.assets.total).toBe(0);
  });
});
