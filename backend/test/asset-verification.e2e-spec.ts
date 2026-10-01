import { INestApplication, ValidationPipe } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { readFileSync } from 'node:fs';
import * as http from 'node:http';
import { AddressInfo } from 'node:net';
import { join } from 'node:path';
import request from 'supertest';
import { TXT_RESOLVER } from '../src/assets/verification/asset-verification.service';
import { PrismaClientExceptionFilter } from '../src/common/filters/prisma-exception.filter';
import { MonitoringScheduler } from '../src/monitoring/monitoring.scheduler';
import { PrismaService } from '../src/prisma/prisma.service';
import { NmapRunner } from '../src/scans/nmap/nmap.runner';
import { NmapRunOutput } from '../src/scans/nmap/nmap.types';
import { ScanWorkerService } from '../src/scans/scan-worker.service';

const FIXTURE = readFileSync(join(__dirname, '..', 'src', 'scans', 'nmap', '__fixtures__', 'localhost-scan.xml'), 'utf8');

/** DNS simulado: nombre -> registros TXT. */
const txt = new Map<string, string[][]>();
const fakeResolver = async (name: string): Promise<string[][]> => {
  const records = txt.get(name);
  if (!records) throw Object.assign(new Error(`queryTxt ENOTFOUND ${name}`), { code: 'ENOTFOUND' });
  return records;
};

/**
 * Sección 1.6.3: solo se escanean activos cuya propiedad se ha demostrado,
 * con un registro DNS TXT o con el archivo de verificación.
 */
describe('Verificación de propiedad de activos (e2e)', () => {
  let app: INestApplication;
  let prisma: PrismaService;
  let site: http.Server;
  /** Respuesta del sitio local para /.well-known/sspm-verification.txt. */
  let fileMode: 'missing' | 'redirect' | 'wrong' | 'ok' = 'missing';
  let proof = '';
  const suffix = Date.now();
  const orgIds: string[] = [];
  let admin: string;
  let viewer: string;
  let otherOrg: string;

  const http_ = () => request(app.getHttpServer());
  const auth = (token: string) => ({ Authorization: `Bearer ${token}` });

  const register = async (org: string, email: string) => {
    const res = await http_()
      .post('/api/v1/auth/register')
      .send({ organizationName: org, fullName: 'Admin', email, password: 'Password123' })
      .expect(201);
    orgIds.push(res.body.user.organizationId);
    return res.body.accessToken as string;
  };

  const createAsset = async (value: string, token = admin) =>
    (await http_().post('/api/v1/assets').set(auth(token)).send({ value, authorizationConfirmed: true }).expect(201)).body;

  beforeAll(async () => {
    site = http.createServer((req, res) => {
      if (req.url !== '/.well-known/sspm-verification.txt' || fileMode === 'missing') {
        res.writeHead(404).end('not found');
      } else if (fileMode === 'redirect') {
        res.writeHead(302, { Location: 'https://attacker.example/proof.txt' }).end();
      } else {
        res.writeHead(200, { 'Content-Type': 'text/plain' }).end(fileMode === 'ok' ? `${proof}\n` : 'otra-cosa');
      }
    });
    await new Promise<void>((resolve) => site.listen(0, '127.0.0.1', resolve));
    const port = (site.address() as AddressInfo).port;

    process.env.ASSET_VERIFICATION_REQUIRED = 'true';
    process.env.ALLOW_PRIVATE_TARGETS = 'true';
    process.env.WEB_HTTP_PORTS = String(port);
    // Puerto HTTPS cerrado: la verificación prueba HTTPS primero y después HTTP.
    process.env.WEB_HTTPS_PORTS = '1';
    process.env.WEB_REQUEST_TIMEOUT_MS = '2000';

    const { AppModule } = await import('../src/app.module');
    const fakeNmap = { run: async (): Promise<NmapRunOutput> => ({ stdout: FIXTURE, stderr: '', exitCode: 0, timedOut: false, cancelled: false, durationMs: 10 }) };
    const moduleRef = await Test.createTestingModule({ imports: [AppModule] })
      .overrideProvider(TXT_RESOLVER)
      .useValue(fakeResolver)
      .overrideProvider(NmapRunner)
      .useValue(fakeNmap)
      .compile();
    app = moduleRef.createNestApplication();
    app.setGlobalPrefix('api/v1');
    app.useGlobalPipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true }));
    app.useGlobalFilters(new PrismaClientExceptionFilter());
    app.enableShutdownHooks();
    await app.init();
    prisma = app.get(PrismaService);

    admin = await register(`Verif Org ${suffix}`, `verif-${suffix}@test.local`);
    otherOrg = await register(`Verif Org B ${suffix}`, `verif-b-${suffix}@test.local`);
    await http_()
      .post('/api/v1/users')
      .set(auth(admin))
      .send({ fullName: 'Gerente', email: `verif-v-${suffix}@test.local`, password: 'Password123', role: 'VIEWER' })
      .expect(201);
    viewer = (await http_().post('/api/v1/auth/login').send({ email: `verif-v-${suffix}@test.local`, password: 'Password123' }).expect(200)).body
      .accessToken;
  });

  afterAll(async () => {
    await prisma.organization.deleteMany({ where: { id: { in: orgIds } } });
    await app.close();
    await new Promise<void>((resolve) => site.close(() => resolve()));
  });

  describe('dominios (registro DNS TXT)', () => {
    let tiendaId: string;
    let wwwId: string;

    it('un activo nuevo no está verificado y no se puede escanear', async () => {
      const tienda = await createAsset('tienda.example.org');
      tiendaId = tienda.id;
      expect(tienda.verifiedAt).toBeNull();

      const status = await http_().get(`/api/v1/assets/${tiendaId}/verification`).set(auth(viewer)).expect(200);
      proof = status.body.proof;
      expect(proof).toMatch(/^sspm-verification=[0-9a-f]{32}$/);
      expect(status.body).toMatchObject({
        verified: false,
        required: true,
        dns: {
          type: 'TXT',
          recordName: '_sspm-verification.tienda.example.org',
          alternatives: ['_sspm-verification.example.org'],
          value: proof,
        },
      });

      const scan = await http_().post(`/api/v1/assets/${tiendaId}/scans`).set(auth(admin)).send({ type: 'PORT_SCAN' }).expect(400);
      expect(scan.body.message).toContain('Verifica');
      await http_().post(`/api/v1/assets/${tiendaId}/scans/all`).set(auth(admin)).expect(400);
    });

    it('sin el registro la verificación falla y explica por qué', async () => {
      wwwId = (await createAsset('www.example.org')).id;
      const res = await http_().post(`/api/v1/assets/${tiendaId}/verify`).set(auth(admin)).send({ method: 'DNS_TXT' }).expect(200);
      expect(res.body.success).toBe(false);
      expect(res.body.attempts.map((a: { target: string }) => a.target)).toEqual([
        '_sspm-verification.tienda.example.org',
        '_sspm-verification.example.org',
      ]);
      expect(res.body.error).toContain('No existe el registro TXT');
      expect(res.body.checkedAt).not.toBeNull();
    });

    it('un TXT con otro valor no sirve', async () => {
      txt.set('_sspm-verification.example.org', [['sspm-verification=00000000000000000000000000000000']]);
      const res = await http_().post(`/api/v1/assets/${tiendaId}/verify`).set(auth(admin)).send({ method: 'DNS_TXT' }).expect(200);
      expect(res.body.success).toBe(false);
    });

    it('el TXT en el dominio padre verifica el activo y los subdominios ya registrados', async () => {
      txt.set('_sspm-verification.example.org', [['v=spf1 -all'], [proof]]);
      await http_().post(`/api/v1/assets/${tiendaId}/verify`).set(auth(viewer)).send({}).expect(403);
      const res = await http_().post(`/api/v1/assets/${tiendaId}/verify`).set(auth(admin)).send({}).expect(200);
      expect(res.body).toMatchObject({ success: true, verified: true, method: 'DNS_TXT', scope: 'example.org', error: null });

      const www = await http_().get(`/api/v1/assets/${wwwId}`).set(auth(admin)).expect(200);
      expect(www.body).toMatchObject({ verificationMethod: 'INHERITED', verificationScope: 'example.org' });
      expect(www.body.verifiedAt).not.toBeNull();
    });

    it('los subdominios que se registran después heredan la verificación', async () => {
      const api = await createAsset('api.example.org');
      expect(api).toMatchObject({ verificationMethod: 'INHERITED', verificationScope: 'example.org' });
      const lookalike = await createAsset('example.org.evil-site.net');
      expect(lookalike.verifiedAt).toBeNull();
    });

    it('la verificación de una organización no vale para otra', async () => {
      const shop = await createAsset('shop.example.org', otherOrg);
      expect(shop.verifiedAt).toBeNull();
      await http_().get(`/api/v1/assets/${tiendaId}/verification`).set(auth(otherOrg)).expect(404);
      await http_().post(`/api/v1/assets/${tiendaId}/verify`).set(auth(otherOrg)).send({}).expect(404);
    });

    it('un activo verificado sí se puede escanear', async () => {
      const res = await http_().post(`/api/v1/assets/${tiendaId}/scans`).set(auth(admin)).send({ type: 'PORT_SCAN' }).expect(202);
      await http_().post(`/api/v1/scans/${res.body.id}/cancel`).set(auth(admin));
    });
  });

  describe('direcciones IP (archivo de verificación)', () => {
    let ipId: string;

    it('las IP no admiten verificación por DNS', async () => {
      ipId = (await createAsset('127.0.0.1')).id;
      const status = await http_().get(`/api/v1/assets/${ipId}/verification`).set(auth(admin)).expect(200);
      expect(status.body.dns).toBeNull();
      expect(status.body.file.urls).toEqual([
        'https://127.0.0.1:1/.well-known/sspm-verification.txt',
        expect.stringMatching(/^http:\/\/127\.0\.0\.1:\d+\/\.well-known\/sspm-verification\.txt$/),
      ]);
      await http_().post(`/api/v1/assets/${ipId}/verify`).set(auth(admin)).send({ method: 'DNS_TXT' }).expect(400);
    });

    it('no sigue redirecciones ni acepta contenido distinto', async () => {
      fileMode = 'redirect';
      let res = await http_().post(`/api/v1/assets/${ipId}/verify`).set(auth(admin)).send({}).expect(200);
      expect(res.body.success).toBe(false);
      expect(res.body.attempts.at(-1).detail).toContain('no se siguen redirecciones');

      fileMode = 'wrong';
      res = await http_().post(`/api/v1/assets/${ipId}/verify`).set(auth(admin)).send({}).expect(200);
      expect(res.body.success).toBe(false);
      expect(res.body.attempts.at(-1).detail).toContain('no coincide');
    });

    it('el archivo correcto verifica la IP', async () => {
      fileMode = 'ok';
      const res = await http_().post(`/api/v1/assets/${ipId}/verify`).set(auth(admin)).send({ method: 'HTTP_FILE' }).expect(200);
      expect(res.body).toMatchObject({ success: true, method: 'HTTP_FILE', scope: '127.0.0.1' });
    });
  });

  describe('monitoreo continuo', () => {
    it('solo planifica activos verificados', async () => {
      const unverified = await createAsset('203.0.113.77');
      await http_().patch('/api/v1/monitoring').set(auth(admin)).send({ frequency: 'DAILY' }).expect(200);
      const status = await http_().get('/api/v1/monitoring').set(auth(admin)).expect(200);
      const byValue = Object.fromEntries(status.body.assets.map((a: { value: string; monitored: boolean }) => [a.value, a.monitored]));
      expect(byValue['203.0.113.77']).toBe(false);
      expect(byValue['tienda.example.org']).toBe(true);

      const worker = app.get(ScanWorkerService);
      const kick = jest.spyOn(worker, 'kick').mockImplementation(() => undefined);
      try {
        await app.get(MonitoringScheduler).runOnce();
        const scans = await http_().get(`/api/v1/scans?assetId=${unverified.id}`).set(auth(admin)).expect(200);
        expect(scans.body.items).toHaveLength(0);
        const pending = await http_().get('/api/v1/scans?status=PENDING&pageSize=100').set(auth(admin)).expect(200);
        for (const s of pending.body.items) await http_().post(`/api/v1/scans/${s.id}/cancel`).set(auth(admin));
      } finally {
        kick.mockRestore();
      }
    });
  });
});
