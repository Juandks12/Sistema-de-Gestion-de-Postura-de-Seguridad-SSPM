import { INestApplication, ValidationPipe } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { readFileSync } from 'node:fs';
import * as http from 'node:http';
import * as https from 'node:https';
import { AddressInfo } from 'node:net';
import { join } from 'node:path';
import request from 'supertest';
import { PrismaClientExceptionFilter } from '../src/common/filters/prisma-exception.filter';
import { PrismaService } from '../src/prisma/prisma.service';

/**
 * Auditoría web (RF-04, RF-05, RF-06) y ciclo de vida de hallazgos (RF-08)
 * contra un servidor local en modo laboratorio.
 */
describe('Web audit (e2e) - cabeceras, TLS, rutas sensibles y hallazgos', () => {
  const fixtures = join(__dirname, 'fixtures', 'tls');
  let httpsServer: https.Server;
  let httpServer: http.Server;
  let httpsPort: number;
  let httpPort: number;
  /** Cuando es true el servidor responde con cabeceras seguras y sin archivos expuestos. */
  let hardened = false;

  let app: INestApplication;
  let prisma: PrismaService;
  const suffix = Date.now();
  const orgIds: string[] = [];
  let token: string;
  let assetId: string;

  const handler = (req: http.IncomingMessage, res: http.ServerResponse) => {
    const url = req.url ?? '/';
    const encrypted = (req.socket as { encrypted?: boolean }).encrypted === true;
    if (hardened && !encrypted) {
      res.writeHead(301, { Location: `https://localhost:${httpsPort}${url}` });
      res.end();
      return;
    }
    if (hardened) {
      res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains');
      res.setHeader('Content-Security-Policy', "default-src 'self'; frame-ancestors 'none'");
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
      res.setHeader('Permissions-Policy', 'camera=()');
    } else {
      res.setHeader('Server', 'Apache/2.4.41 (Ubuntu)');
      res.setHeader('X-Powered-By', 'PHP/7.4.3');
      res.setHeader('Set-Cookie', 'PHPSESSID=abc123; Path=/');
    }

    const exposed: Record<string, [string, string]> = hardened
      ? {}
      : {
          '/.env': ['text/plain', 'APP_ENV=production\nAPP_KEY=base64:secret\nDB_PASSWORD=hunter2\n'],
          '/.git/HEAD': ['text/plain', 'ref: refs/heads/main\n'],
          '/phpinfo.php': ['text/html', '<html><body><h1>PHP Version 7.4.3</h1></body></html>'],
          '/uploads/': ['text/html', '<html><title>Index of /uploads</title></html>'],
        };

    if (url === '/') {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('<html><body>Sitio de pruebas SSPM</body></html>');
      return;
    }
    if (exposed[url]) {
      res.writeHead(200, { 'Content-Type': exposed[url][0] });
      res.end(exposed[url][1]);
      return;
    }
    res.writeHead(404, { 'Content-Type': 'text/html' });
    res.end('<html><body>Not found</body></html>');
  };

  const http_ = () => request(app.getHttpServer());

  const runScan = async (type: string) => {
    const res = await http_()
      .post(`/api/v1/assets/${assetId}/scans`)
      .set('Authorization', `Bearer ${token}`)
      .send({ type })
      .expect(202);
    const deadline = Date.now() + 30000;
    for (;;) {
      const scan = await http_().get(`/api/v1/scans/${res.body.id}`).set('Authorization', `Bearer ${token}`).expect(200);
      if (['COMPLETED', 'FAILED', 'CANCELLED'].includes(scan.body.status)) return scan.body;
      if (Date.now() > deadline) throw new Error(`Escaneo ${type} no terminó a tiempo`);
      await new Promise((r) => setTimeout(r, 100));
    }
  };

  const openFindings = async (category?: string) => {
    const res = await http_()
      .get(`/api/v1/findings?assetId=${assetId}&status=OPEN&pageSize=100${category ? `&category=${category}` : ''}`)
      .set('Authorization', `Bearer ${token}`)
      .expect(200);
    return res.body.items as Array<{ id: string; ruleId: string; location: string; severity: string; status: string }>;
  };

  beforeAll(async () => {
    httpsServer = https.createServer(
      { key: readFileSync(join(fixtures, 'localhost-key.pem')), cert: readFileSync(join(fixtures, 'localhost-cert.pem')) },
      handler,
    );
    httpServer = http.createServer(handler);
    await new Promise<void>((resolve) => httpsServer.listen(0, '127.0.0.1', resolve));
    await new Promise<void>((resolve) => httpServer.listen(0, '127.0.0.1', resolve));
    httpsPort = (httpsServer.address() as AddressInfo).port;
    httpPort = (httpServer.address() as AddressInfo).port;

    // Configuración de laboratorio: objetivos locales y puertos de prueba.
    process.env.ALLOW_PRIVATE_TARGETS = 'true';
    process.env.WEB_HTTPS_PORTS = String(httpsPort);
    process.env.WEB_HTTP_PORTS = String(httpPort);
    process.env.WEB_REQUEST_TIMEOUT_MS = '5000';
    process.env.SCAN_POLL_INTERVAL_MS = '500';

    // ConfigModule.forRoot valida el entorno al importar AppModule, por eso se importa aquí.
    const { AppModule } = await import('../src/app.module');
    const moduleRef = await Test.createTestingModule({ imports: [AppModule] }).compile();
    app = moduleRef.createNestApplication();
    app.setGlobalPrefix('api/v1');
    app.useGlobalPipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true }));
    app.useGlobalFilters(new PrismaClientExceptionFilter());
    app.enableShutdownHooks();
    await app.init();
    prisma = app.get(PrismaService);

    const reg = await http_()
      .post('/api/v1/auth/register')
      .send({ organizationName: `Web Org ${suffix}`, fullName: 'Test', email: `web-${suffix}@test.local`, password: 'Password123' })
      .expect(201);
    orgIds.push(reg.body.user.organizationId);
    token = reg.body.accessToken;

    const asset = await http_()
      .post('/api/v1/assets')
      .set('Authorization', `Bearer ${token}`)
      .send({ value: 'localhost', name: 'Servidor de pruebas', authorizationConfirmed: true })
      .expect(201);
    assetId = asset.body.id;
  });

  afterAll(async () => {
    await prisma.organization.deleteMany({ where: { id: { in: orgIds } } });
    await app.close();
    await new Promise<void>((resolve) => httpsServer.close(() => resolve()));
    await new Promise<void>((resolve) => httpServer.close(() => resolve()));
  });

  it('RF-04: audita las cabeceras HTTP por HTTPS y HTTP', async () => {
    const scan = await runScan('WEB_HEADERS');
    expect(scan.status).toBe('COMPLETED');
    expect(scan.summary.targetsReachable).toBe(2);
    expect(scan.summary.httpsAvailable).toBe(true);

    const rules = (await openFindings('HTTP_HEADERS')).map((f) => f.ruleId);
    expect(rules).toEqual(
      expect.arrayContaining([
        'HDR-HSTS-MISSING',
        'HDR-CSP-MISSING',
        'HDR-XFO-MISSING',
        'HDR-XCTO-MISSING',
        'HDR-SERVER-VERSION',
        'HDR-POWERED-BY',
        'HDR-COOKIE-INSECURE',
        'HDR-COOKIE-NO-HTTPONLY',
        'HDR-HTTP-NO-REDIRECT',
      ]),
    );
  });

  it('RF-05: valida el certificado TLS (autofirmado)', async () => {
    const scan = await runScan('SSL_CERT');
    expect(scan.status).toBe('COMPLETED');
    expect(scan.summary.portsWithTls).toBe(1);
    expect(scan.summary.certificate.subject).toContain('CN=localhost');

    const findings = await openFindings('TLS_CERTIFICATE');
    const untrusted = findings.find((f) => f.ruleId === 'TLS-UNTRUSTED-CHAIN');
    expect(untrusted).toBeDefined();
    expect(untrusted!.severity).toBe('HIGH');
    expect(untrusted!.location).toBe(`tls://localhost:${httpsPort}`);
    expect(findings.map((f) => f.ruleId)).not.toContain('TLS-HOSTNAME-MISMATCH');
    expect(findings.map((f) => f.ruleId)).not.toContain('TLS-EXPIRED');
  });

  it('RF-06: detecta rutas sensibles con firma de contenido y sin guardar su contenido', async () => {
    const scan = await runScan('SENSITIVE_PATHS');
    expect(scan.status).toBe('COMPLETED');
    expect(scan.summary.softNotFound).toBe(false);
    expect(scan.summary.baseUrl).toBe(`https://localhost:${httpsPort}`);

    const findings = await openFindings('SENSITIVE_PATH');
    const byPath = Object.fromEntries(findings.map((f) => [new URL(f.location).pathname, f]));
    expect(byPath['/.env']).toMatchObject({ ruleId: 'PATH-SECRETS-EXPOSED', severity: 'CRITICAL' });
    expect(byPath['/.git/HEAD']).toMatchObject({ ruleId: 'PATH-VCS-EXPOSED', severity: 'HIGH' });
    expect(byPath['/phpinfo.php']).toMatchObject({ ruleId: 'PATH-DEBUG-INFO', severity: 'MEDIUM' });
    expect(byPath['/uploads/']).toMatchObject({ ruleId: 'PATH-DIRECTORY-LISTING' });
    expect(Object.keys(byPath)).toHaveLength(4);

    const detail = await http_().get(`/api/v1/findings/${byPath['/.env'].id}`).set('Authorization', `Bearer ${token}`).expect(200);
    expect(JSON.stringify(detail.body.evidence)).not.toContain('hunter2');
    expect(JSON.stringify(scan.rawResult ?? {})).not.toContain('hunter2');
  });

  it('RF-08: el resumen agrupa los hallazgos abiertos por severidad y categoría', async () => {
    const res = await http_().get(`/api/v1/findings/summary?assetId=${assetId}`).set('Authorization', `Bearer ${token}`).expect(200);
    expect(res.body.bySeverity.CRITICAL).toBeGreaterThanOrEqual(1);
    expect(res.body.bySeverity.HIGH).toBeGreaterThanOrEqual(2);
    expect(res.body.byCategory.HTTP_HEADERS).toBeGreaterThan(0);
    expect(res.body.byCategory.TLS_CERTIFICATE).toBeGreaterThan(0);
    expect(res.body.byCategory.SENSITIVE_PATH).toBe(4);
    expect(res.body.total).toBe(
      Object.values(res.body.bySeverity as Record<string, number>).reduce((a, b) => a + b, 0),
    );
  });

  it('RF-08: los hallazgos se deduplican entre escaneos y se resuelven al corregirse', async () => {
    const before = await openFindings('HTTP_HEADERS');
    const hstsBefore = before.find((f) => f.ruleId === 'HDR-HSTS-MISSING')!;

    // Mismo escaneo otra vez: mismos hallazgos, sin duplicados.
    await runScan('WEB_HEADERS');
    const again = await openFindings('HTTP_HEADERS');
    expect(again).toHaveLength(before.length);
    expect(again.find((f) => f.ruleId === 'HDR-HSTS-MISSING')!.id).toBe(hstsBefore.id);

    // El administrador acepta el riesgo de una cabecera informativa.
    const permissions = again.find((f) => f.ruleId === 'HDR-PERMISSIONS-MISSING')!;
    const reviewed = await http_()
      .patch(`/api/v1/findings/${permissions.id}`)
      .set('Authorization', `Bearer ${token}`)
      .send({ status: 'ACCEPTED', note: 'No aplica a esta aplicación' })
      .expect(200);
    expect(reviewed.body.status).toBe('ACCEPTED');
    expect(reviewed.body.reviewedBy.email).toBe(`web-${suffix}@test.local`);

    // Se corrige el servidor: los hallazgos abiertos pasan a RESOLVED y el aceptado se conserva.
    hardened = true;
    const scan = await runScan('WEB_HEADERS');
    expect(scan.summary.findings.resolved).toBeGreaterThan(0);
    expect(await openFindings('HTTP_HEADERS')).toEqual([]);

    const all = await http_()
      .get(`/api/v1/findings?assetId=${assetId}&category=HTTP_HEADERS&pageSize=100`)
      .set('Authorization', `Bearer ${token}`)
      .expect(200);
    const statuses = Object.fromEntries(all.body.items.map((f: { ruleId: string; status: string }) => [f.ruleId, f.status]));
    expect(statuses['HDR-HSTS-MISSING']).toBe('RESOLVED');
    expect(statuses['HDR-PERMISSIONS-MISSING']).toBe('ACCEPTED');

    // Los hallazgos de otras categorías no se ven afectados por este escaneo.
    expect((await openFindings('TLS_CERTIFICATE')).length).toBeGreaterThan(0);

    // Si el problema vuelve, el mismo hallazgo se reabre.
    hardened = false;
    await runScan('WEB_HEADERS');
    const reopened = await openFindings('HTTP_HEADERS');
    expect(reopened.find((f) => f.ruleId === 'HDR-HSTS-MISSING')!.id).toBe(hstsBefore.id);
  });

  it('la auditoría completa encola todos los tipos y omite los que ya están en curso', async () => {
    const res = await http_().post(`/api/v1/assets/${assetId}/scans/all`).set('Authorization', `Bearer ${token}`).expect(202);
    expect(res.body.queued.map((s: { type: string }) => s.type).sort()).toEqual(
      ['PORT_SCAN', 'SENSITIVE_PATHS', 'SSL_CERT', 'WEB_HEADERS'].sort(),
    );
    const second = await http_().post(`/api/v1/assets/${assetId}/scans/all`).set('Authorization', `Bearer ${token}`).expect(202);
    expect(second.body.queued).toHaveLength(0);
    expect(second.body.skipped).toHaveLength(4);
    for (const s of res.body.queued) {
      await http_().post(`/api/v1/scans/${s.id}/cancel`).set('Authorization', `Bearer ${token}`);
    }
  });

  it('otra organización no ve los hallazgos', async () => {
    const other = await http_()
      .post('/api/v1/auth/register')
      .send({ organizationName: `Web Org B ${suffix}`, fullName: 'Beto', email: `web-b-${suffix}@test.local`, password: 'Password123' })
      .expect(201);
    orgIds.push(other.body.user.organizationId);
    const list = await http_().get('/api/v1/findings').set('Authorization', `Bearer ${other.body.accessToken}`).expect(200);
    expect(list.body.meta.total).toBe(0);
    const [first] = await openFindings();
    await http_().get(`/api/v1/findings/${first.id}`).set('Authorization', `Bearer ${other.body.accessToken}`).expect(404);
  });
});
