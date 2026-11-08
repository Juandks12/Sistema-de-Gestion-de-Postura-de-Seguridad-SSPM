import { INestApplication, ValidationPipe } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import { PrismaClientExceptionFilter } from '../src/common/filters/prisma-exception.filter';
import { PrismaService } from '../src/prisma/prisma.service';

/**
 * Sprint 21–24 E2E:
 * - Salud operacional extendida (/api/v1/health)
 * - Laboratorio de Malware y Phishing (/api/v1/threat-lab) + Promoción a Hallazgo GRC
 * - Catálogo GRC Unificado y Matriz de Cumplimiento (/api/v1/findings/grc-catalog, /api/v1/compliance)
 * - API Pública SIEM/SOAR extendida (/api/v1/public/threat-lab, /api/v1/public/compliance)
 * - Retención extendida de Lotes 360° y Threat Lab (/api/v1/retention/run)
 */
describe('Threat Lab, GRC Compliance, API Pública SIEM y Salud Operacional (e2e)', () => {
  let app: INestApplication;
  let prisma: PrismaService;
  const suffix = Date.now();
  const orgIds: string[] = [];

  let adminToken: string;
  let assetId: string;
  let emailAnalysisId: string;
  let rawApiKey: string;

  const http_ = () => request(app.getHttpServer());
  const auth = (token: string) => ({ Authorization: `Bearer ${token}` });

  beforeAll(async () => {
    process.env.ALLOW_PRIVATE_TARGETS = 'true';
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
      .send({
        organizationName: `ThreatLab GRC Org ${suffix}`,
        fullName: 'CISO Test',
        email: `ciso-${suffix}@test.local`,
        password: 'Password123',
      })
      .expect(201);
    orgIds.push(reg.body.user.organizationId);
    adminToken = reg.body.accessToken;

    const asset = await http_()
      .post('/api/v1/assets')
      .set(auth(adminToken))
      .send({
        value: '45.33.32.156',
        name: 'Gateway Corporativo',
        criticality: 'CRITICAL',
        authorizationConfirmed: true,
      })
      .expect(201);
    assetId = asset.body.id;

    const keyRes = await http_()
      .post('/api/v1/api-keys')
      .set(auth(adminToken))
      .send({
        name: 'Conector SIEM Splunk',
        scopes: ['findings:read', 'alerts:read', 'posture:read', 'assets:read'],
      })
      .expect(201);
    rawApiKey = keyRes.body.rawKey;
  });

  afterAll(async () => {
    await prisma.organization.deleteMany({ where: { id: { in: orgIds } } });
    await app.close();
  });

  describe('Salud operacional (/api/v1/health)', () => {
    it('retorna estado de base de datos, subsistemas y cola de trabajo', async () => {
      const res = await http_().get('/api/v1/health').expect(200);
      expect(res.body).toMatchObject({
        status: 'ok',
        database: 'up',
        version: '3.0.0',
        subsystems: {
          threatLab: 'ready',
          grcCompliance: 'ready',
        },
        queue: {
          pendingScans: expect.any(Number),
          runningScans: expect.any(Number),
          activeDiagnosticBatches: expect.any(Number),
        },
      });
    });
  });

  describe('Laboratorio de Malware y Phishing (/api/v1/threat-lab)', () => {
    it('analiza un correo malicioso (.eml) con indicadores BEC y suplantación SPF/DMARC', async () => {
      const rawEmail = [
        'From: "CEO Urgente" <ceo@empresa-corporativa.com>',
        'Reply-To: atacante-bec@gmail.com',
        'To: finanzas@empresa-corporativa.com',
        'Subject: URGENTE transferencia bancaria confidencial hoy',
        'Authentication-Results: mx.google.com; spf=fail; dkim=fail; dmarc=fail',
        'Content-Type: text/html; charset="UTF-8"',
        '',
        '<html><body>Por favor procese el pago inmediato en <a href="http://198.51.100.45/login-office365">Portal Pagos</a> y revise factura.pdf.exe</body></html>',
      ].join('\r\n');

      const res = await http_()
        .post('/api/v1/threat-lab/analyze/email')
        .set(auth(adminToken))
        .send({
          artifactName: 'urgente-transferencia.eml',
          rawContent: rawEmail,
          assetId,
        })
        .expect(201);

      emailAnalysisId = res.body.id;
      expect(res.body.artifactType).toBe('EMAIL');
      expect(['MALICIOUS', 'SUSPICIOUS']).toContain(res.body.verdict);
      expect(res.body.riskScore).toBeGreaterThanOrEqual(50);
      expect(res.body.indicators.length).toBeGreaterThan(0);
    });

    it('analiza una URL de phishing y promueve el análisis de correo a Hallazgo GRC formal', async () => {
      const urlRes = await http_()
        .post('/api/v1/threat-lab/analyze/url')
        .set(auth(adminToken))
        .send({
          url: 'http://microsoft-login-security-verify.tk/@evil.example.com/auth.exe',
          assetId,
        })
        .expect(201);

      expect(urlRes.body.artifactType).toBe('URL');
      expect(['MALICIOUS', 'SUSPICIOUS']).toContain(urlRes.body.verdict);

      const promoted = await http_()
        .post(`/api/v1/threat-lab/${emailAnalysisId}/promote-finding`)
        .set(auth(adminToken))
        .send({
          assetId,
          customTitle: 'Incidente BEC detectado en pasarela de correo',
        })
        .expect(201);

      expect(promoted.body.finding).toBeDefined();
      expect(promoted.body.finding.ruleId).toBe('THREAT-EMAIL-PHISHING-BEC');
      expect(promoted.body.analysis.promotedFindingId).toBe(promoted.body.finding.id);
    });
  });

  describe('Catálogo GRC y API Pública SIEM/SOAR', () => {
    it('consulta el catálogo GRC enriquecido y el cumplimiento normativo', async () => {
      const catalog = await http_()
        .get('/api/v1/findings/grc-catalog')
        .set(auth(adminToken))
        .expect(200);
      expect(catalog.body.totalRules).toBeGreaterThanOrEqual(70);
      expect(catalog.body.items[0]).toHaveProperty('mitreTechniques');
      expect(catalog.body.items[0]).toHaveProperty('complianceControls');

      const comp = await http_()
        .get('/api/v1/compliance')
        .set(auth(adminToken))
        .expect(200);
      expect(comp.body.totalFrameworks).toBe(5);
      expect(comp.body.frameworks).toHaveLength(5);
    });

    it('exporta Threat Lab y Compliance mediante la API Pública SIEM (X-API-Key)', async () => {
      const pubThreat = await http_()
        .get('/api/v1/public/threat-lab')
        .set('X-API-Key', rawApiKey)
        .expect(200);
      expect(pubThreat.body.items.length).toBeGreaterThanOrEqual(2);

      const pubComp = await http_()
        .get('/api/v1/public/compliance?framework=ISO_27001')
        .set('X-API-Key', rawApiKey)
        .expect(200);
      expect(pubComp.body.overview.totalFrameworks).toBe(5);
      expect(pubComp.body.frameworkDetail.metadata.id).toBe('ISO_27001');
    });

    it('ejecuta la política de retención extendida incluyendo contadores de Lotes 360° y Threat Lab', async () => {
      const ret = await http_()
        .post('/api/v1/retention/run')
        .set(auth(adminToken))
        .expect(200);
      expect(ret.body).toHaveProperty('diagnosticBatchesPurged');
      expect(ret.body).toHaveProperty('malwareAnalysesPurged');
    });
  });
});
