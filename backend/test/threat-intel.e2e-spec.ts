import { INestApplication, ValidationPipe } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import request from 'supertest';
import { DNS_CLIENT } from '../src/common/dns/dns-client';
import { fakeDns, FakeZone } from '../src/common/dns/fake-dns';
import { PrismaClientExceptionFilter } from '../src/common/filters/prisma-exception.filter';
import { CT_SOURCE, CtSource } from '../src/discovery/ct-log.client';
import { CtName } from '../src/discovery/hostnames';
import { PrismaService } from '../src/prisma/prisma.service';
import { NmapRunner } from '../src/scans/nmap/nmap.runner';
import { ScanWorkerService } from '../src/scans/scan-worker.service';
import { NmapRunOutput } from '../src/scans/nmap/nmap.types';
import { CveEntry } from '../src/vulnerabilities/cve-data';
import { CVE_SOURCE, CveSource, CveSourceError } from '../src/vulnerabilities/nvd.client';

const FIXTURE = readFileSync(join(__dirname, '..', 'src', 'scans', 'nmap', '__fixtures__', 'localhost-scan.xml'), 'utf8');

/** El fixture de Nmap detecta SimpleHTTPServer 0.6 (cpe:/a:python:simplehttpserver:0.6) en tcp/8089. */
const PRODUCT = 'python:simplehttpserver';

const CVES: CveEntry[] = [
  {
    id: 'CVE-2099-0001',
    published: '2099-01-01T00:00:00',
    cvss: 9.8,
    severity: 'CRITICAL',
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    kev: { added: '2099-01-02', dueDate: '2099-01-23', name: 'Ejecución remota' },
    description: 'Ejecución remota de código.',
    ranges: [{ v: '*', ee: '0.7' }],
  },
  {
    id: 'CVE-2099-0002',
    published: '2099-02-01T00:00:00',
    cvss: 5.3,
    severity: 'MEDIUM',
    vector: null,
    kev: null,
    description: 'Revelación de rutas.',
    ranges: [{ v: '0.6' }],
  },
  {
    id: 'CVE-2099-0003',
    published: '2099-03-01T00:00:00',
    cvss: 7.5,
    severity: 'HIGH',
    vector: null,
    kev: null,
    description: 'No afecta a la 0.6.',
    ranges: [{ v: '*', si: '0.7', ee: '0.9' }],
  },
];

class FakeCveSource implements CveSource {
  fail = false;
  calls = 0;
  async productCves(vendor: string, product: string) {
    this.calls += 1;
    if (this.fail) throw new CveSourceError('NVD respondió 503');
    return `${vendor}:${product}` === PRODUCT ? { total: CVES.length, entries: CVES } : { total: 0, entries: [] };
  }
}

class FakeCtSource implements CtSource {
  names_: CtName[] = [];
  async names() {
    return { source: 'crt.sh', names: this.names_ };
  }
}

class FakeNmapRunner {
  async run(): Promise<NmapRunOutput> {
    return { stdout: FIXTURE, stderr: '', exitCode: 0, timedOut: false, cancelled: false, durationMs: 10 };
  }
}

/**
 * Bloque 2: correlación de CVE, seguridad del correo (SPF/DMARC/DKIM) y
 * descubrimiento de subdominios en Certificate Transparency.
 */
describe('Inteligencia de amenazas (e2e) - CVE, correo y subdominios', () => {
  let app: INestApplication;
  let prisma: PrismaService;
  const suffix = Date.now();
  const domain = `acme${suffix}.com`;
  const orgIds: string[] = [];
  const cveSource = new FakeCveSource();
  const ct = new FakeCtSource();
  const zone: FakeZone = { txt: {}, mx: {}, addresses: {} };
  let token: string;
  let viewerToken: string;
  let ipAssetId: string;
  let domainAssetId: string;

  const http_ = () => request(app.getHttpServer());
  const auth = (t = token) => ({ Authorization: `Bearer ${t}` });

  const runScan = async (assetId: string, type: string) => {
    const queued = await http_().post(`/api/v1/assets/${assetId}/scans`).set(auth()).send({ type }).expect(202);
    const deadline = Date.now() + 15000;
    for (;;) {
      const res = await http_().get(`/api/v1/scans/${queued.body.id}`).set(auth()).expect(200);
      if (['COMPLETED', 'FAILED', 'CANCELLED'].includes(res.body.status)) return res.body;
      if (Date.now() > deadline) throw new Error(`El escaneo ${type} sigue en ${res.body.status}`);
      await new Promise((r) => setTimeout(r, 100));
    }
  };

  const findings = async (assetId: string, category: string, status?: string) =>
    (
      await http_()
        .get('/api/v1/findings')
        .query({ assetId, category, ...(status ? { status } : {}), pageSize: 100 })
        .set(auth())
        .expect(200)
    ).body.items as Array<{ id: string; ruleId: string; status: string; severity: string; cvssScore: string; location: string; evidence: Record<string, unknown> }>;

  const waitForAlerts = async (type: string, count: number) => {
    const deadline = Date.now() + 5000;
    for (;;) {
      const res = await http_().get('/api/v1/alerts').query({ type }).set(auth()).expect(200);
      if (res.body.items.length >= count || Date.now() > deadline) return res.body.items;
      await new Promise((r) => setTimeout(r, 100));
    }
  };

  beforeAll(async () => {
    process.env.CVE_LOOKUP_ENABLED = 'true';
    process.env.SUBDOMAIN_DISCOVERY_ENABLED = 'true';
    const { AppModule } = await import('../src/app.module');
    const moduleRef = await Test.createTestingModule({ imports: [AppModule] })
      .overrideProvider(NmapRunner)
      .useValue(new FakeNmapRunner())
      .overrideProvider(CVE_SOURCE)
      .useValue(cveSource)
      .overrideProvider(CT_SOURCE)
      .useValue(ct)
      .overrideProvider(DNS_CLIENT)
      .useValue(fakeDns(zone))
      .compile();
    app = moduleRef.createNestApplication();
    app.setGlobalPrefix('api/v1');
    app.useGlobalPipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true }));
    app.useGlobalFilters(new PrismaClientExceptionFilter());
    await app.init();
    prisma = app.get(PrismaService);
    await prisma.cveProductCache.deleteMany({ where: { product: PRODUCT } });

    const reg = await http_()
      .post('/api/v1/auth/register')
      .send({ organizationName: `TI Org ${suffix}`, fullName: 'Ana', email: `ti-${suffix}@test.local`, password: 'Password123' })
      .expect(201);
    token = reg.body.accessToken;
    orgIds.push(reg.body.user.organizationId);
    await http_()
      .post('/api/v1/users')
      .set(auth())
      .send({ fullName: 'Lectora', email: `ti-v-${suffix}@test.local`, password: 'Password123', role: 'VIEWER' })
      .expect(201);
    viewerToken = (await http_().post('/api/v1/auth/login').send({ email: `ti-v-${suffix}@test.local`, password: 'Password123' }).expect(200))
      .body.accessToken;

    ipAssetId = (await http_().post('/api/v1/assets').set(auth()).send({ value: '45.33.32.156', authorizationConfirmed: true }).expect(201)).body.id;
    domainAssetId = (await http_().post('/api/v1/assets').set(auth()).send({ value: domain, authorizationConfirmed: true }).expect(201)).body.id;
  });

  afterAll(async () => {
    await prisma.cveProductCache.deleteMany({ where: { product: PRODUCT } });
    await prisma.organization.deleteMany({ where: { id: { in: orgIds } } });
    await app.close();
  });

  describe('CVE de las versiones detectadas', () => {
    it('genera un hallazgo con los CVE que afectan a la versión y prioriza los KEV', async () => {
      const scan = await runScan(ipAssetId, 'PORT_SCAN');
      expect(scan.status).toBe('COMPLETED');
      expect(scan.summary.cve).toMatchObject({ enabled: true, vulnerableServices: 1, totalCves: 2, kevCves: 1 });
      expect(scan.summary.cve.products).toEqual([{ product: PRODUCT, versions: ['0.6'], from: 'nvd', cves: 3 }]);

      const [finding] = await findings(ipAssetId, 'VULNERABLE_SOFTWARE');
      expect(finding).toMatchObject({ ruleId: 'VULN-KNOWN-CVE', location: 'tcp/8089', severity: 'CRITICAL', status: 'OPEN' });
      expect(Number(finding.cvssScore)).toBe(9.8);
      expect((finding.evidence.cves as Array<{ id: string }>).map((c) => c.id)).toEqual(['CVE-2099-0001', 'CVE-2099-0002']);

      // El hallazgo crítico genera una alerta temprana.
      const alerts = await waitForAlerts('CRITICAL_FINDING', 1);
      expect(alerts[0].title).toContain('SimpleHTTPServer 0.6');
    });

    it('reutiliza la caché de NVD en los escaneos siguientes', async () => {
      const calls = cveSource.calls;
      const scan = await runScan(ipAssetId, 'PORT_SCAN');
      expect(scan.summary.cve.products[0].from).toBe('cache');
      expect(cveSource.calls).toBe(calls);
    });

    it('si NVD no responde conserva los hallazgos en lugar de darlos por resueltos', async () => {
      await prisma.cveProductCache.deleteMany({ where: { product: PRODUCT } });
      cveSource.fail = true;
      try {
        const scan = await runScan(ipAssetId, 'PORT_SCAN');
        expect(scan.status).toBe('COMPLETED');
        expect(scan.summary.cve.products[0]).toMatchObject({ from: 'none', error: 'NVD respondió 503' });
        expect(await findings(ipAssetId, 'VULNERABLE_SOFTWARE', 'OPEN')).toHaveLength(1);
      } finally {
        cveSource.fail = false;
      }
    });
  });

  describe('Seguridad del correo', () => {
    it('solo aplica a dominios', async () => {
      await http_().post(`/api/v1/assets/${ipAssetId}/scans`).set(auth()).send({ type: 'EMAIL_SECURITY' }).expect(400);
      // Se pausa el worker: solo interesa qué se encola, no ejecutar los escaneos web contra la IP real.
      const kick = jest.spyOn(app.get(ScanWorkerService), 'kick').mockImplementation(() => {});
      try {
        const all = await http_().post(`/api/v1/assets/${ipAssetId}/scans/all`).set(auth()).expect(202);
        expect(all.body.queued.map((s: { type: string }) => s.type).sort()).toEqual(['PORT_SCAN', 'SENSITIVE_PATHS', 'SSL_CERT', 'WEB_HEADERS']);
        for (const s of all.body.queued) await http_().post(`/api/v1/scans/${s.id}/cancel`).set(auth()).expect(200);
      } finally {
        kick.mockRestore();
      }
    });

    it('detecta un dominio sin SPF, DMARC ni DKIM y los resuelve al corregirlos', async () => {
      zone.mx![domain] = [{ exchange: `mail.${domain}`, priority: 10 }];
      const first = await runScan(domainAssetId, 'EMAIL_SECURITY');
      expect(first.status).toBe('COMPLETED');
      expect(first.targetAddress).toBeNull();
      const open = await findings(domainAssetId, 'EMAIL_SECURITY', 'OPEN');
      expect(open.map((f) => f.ruleId).sort()).toEqual(['MAIL-DKIM-NOT-FOUND', 'MAIL-DMARC-MISSING', 'MAIL-SPF-MISSING']);

      zone.txt![domain] = ['v=spf1 mx -all'];
      zone.txt![`_dmarc.${domain}`] = [`v=DMARC1; p=none; rua=mailto:dmarc@${domain}`];
      const second = await runScan(domainAssetId, 'EMAIL_SECURITY');
      expect(second.summary.findings).toMatchObject({ resolved: 2 });
      expect((await findings(domainAssetId, 'EMAIL_SECURITY', 'OPEN')).map((f) => f.ruleId).sort()).toEqual([
        'MAIL-DKIM-NOT-FOUND',
        'MAIL-DMARC-MONITOR-ONLY',
      ]);
    });

    it('un fallo del DNS hace fallar el escaneo sin tocar los hallazgos', async () => {
      zone.mx![domain] = 'SERVFAIL';
      const scan = await runScan(domainAssetId, 'EMAIL_SECURITY');
      expect(scan.status).toBe('FAILED');
      expect(scan.errorMessage).toContain('ESERVFAIL');
      expect(await findings(domainAssetId, 'EMAIL_SECURITY', 'OPEN')).toHaveLength(2);
      zone.mx![domain] = [{ exchange: `mail.${domain}`, priority: 10 }];
    });
  });

  describe('Descubrimiento de subdominios', () => {
    it('el primer descubrimiento es la línea base y no alerta', async () => {
      ct.names_ = [
        { name: `www.${domain}\n${domain}`, notBefore: '2099-01-01T00:00:00' },
        { name: `*.dev.${domain}`, notBefore: '2099-02-01T00:00:00' },
        { name: `vpn.${domain}`, notBefore: '2099-03-01T00:00:00' },
        { name: 'otro-dominio.com', notBefore: null },
      ];
      zone.addresses![`www.${domain}`] = ['93.184.216.34'];
      zone.addresses![`vpn.${domain}`] = ['10.0.0.5'];

      const scan = await runScan(domainAssetId, 'SUBDOMAIN_DISCOVERY');
      expect(scan.status).toBe('COMPLETED');
      expect(scan.summary).toMatchObject({ source: 'crt.sh', subdomains: 3, resolving: 2, discovery: { baseline: true, new: 3 } });

      const list = await http_().get(`/api/v1/assets/${domainAssetId}/discovered-hosts`).set(auth()).expect(200);
      expect(list.body.summary).toMatchObject({ total: 3, resolving: 2, pending: 3 });
      const byName = Object.fromEntries(list.body.items.map((h: { hostname: string }) => [h.hostname, h]));
      expect(byName[`dev.${domain}`]).toMatchObject({ wildcard: true, resolves: false });
      expect(byName[`vpn.${domain}`]).toMatchObject({ internal: true, addresses: ['10.0.0.5'] });
      expect(await waitForAlerts('NEW_SUBDOMAIN', 0)).toHaveLength(0);
    });

    it('alerta solo de los subdominios nuevos fuera del inventario', async () => {
      await http_().post('/api/v1/assets').set(auth()).send({ value: `shop.${domain}`, authorizationConfirmed: true }).expect(201);
      ct.names_ = [...ct.names_, { name: `staging.${domain}`, notBefore: null }, { name: `shop.${domain}`, notBefore: null }];
      const scan = await runScan(domainAssetId, 'SUBDOMAIN_DISCOVERY');
      expect(scan.summary.discovery).toMatchObject({ baseline: false, new: 2 });

      const [alert] = await waitForAlerts('NEW_SUBDOMAIN', 1);
      expect(alert).toMatchObject({ severity: 'MEDIUM', data: { hosts: [`staging.${domain}`] } });

      const list = await http_().get(`/api/v1/assets/${domainAssetId}/discovered-hosts`).set(auth()).expect(200);
      expect(list.body.items.find((h: { hostname: string }) => h.hostname === `shop.${domain}`).inventoryAssetId).toBeTruthy();
    });

    it('permite descartar e incorporar subdominios al inventario', async () => {
      const list = await http_().get(`/api/v1/assets/${domainAssetId}/discovered-hosts`).set(auth()).expect(200);
      const id = (name: string) => list.body.items.find((h: { hostname: string }) => h.hostname === `${name}.${domain}`).id;

      await http_().patch(`/api/v1/discovered-hosts/${id('dev')}`).set(auth(viewerToken)).send({ ignored: true }).expect(403);
      const ignored = await http_().patch(`/api/v1/discovered-hosts/${id('dev')}`).set(auth()).send({ ignored: true }).expect(200);
      expect(ignored.body).toMatchObject({ hostname: `dev.${domain}`, ignored: true });

      await http_()
        .post('/api/v1/discovered-hosts/import')
        .set(auth())
        .send({ ids: [id('www')], authorizationConfirmed: false })
        .expect(400);
      const imported = await http_()
        .post('/api/v1/discovered-hosts/import')
        .set(auth())
        .send({ ids: [id('www'), id('shop')], authorizationConfirmed: true })
        .expect(201);
      expect(imported.body.created.map((c: { hostname: string }) => c.hostname)).toEqual([`www.${domain}`]);
      expect(imported.body.failed).toEqual([{ hostname: `shop.${domain}`, reason: 'Ya está en el inventario' }]);

      const after = await http_().get(`/api/v1/assets/${domainAssetId}/discovered-hosts`).set(auth()).expect(200);
      expect(after.body.summary).toMatchObject({ total: 5, ignored: 1, inInventory: 2, pending: 2 });
    });

    it('otra organización no ve ni modifica los subdominios', async () => {
      const other = await http_()
        .post('/api/v1/auth/register')
        .send({ organizationName: `TI Org B ${suffix}`, fullName: 'Beto', email: `ti-b-${suffix}@test.local`, password: 'Password123' })
        .expect(201);
      orgIds.push(other.body.user.organizationId);
      const list = await http_().get(`/api/v1/assets/${domainAssetId}/discovered-hosts`).set(auth()).expect(200);
      await http_().get(`/api/v1/assets/${domainAssetId}/discovered-hosts`).set(auth(other.body.accessToken)).expect(404);
      await http_()
        .patch(`/api/v1/discovered-hosts/${list.body.items[0].id}`)
        .set(auth(other.body.accessToken))
        .send({ ignored: true })
        .expect(404);
      await http_()
        .post('/api/v1/discovered-hosts/import')
        .set(auth(other.body.accessToken))
        .send({ ids: [list.body.items[0].id], authorizationConfirmed: true })
        .expect(404);
    });
  });
});
