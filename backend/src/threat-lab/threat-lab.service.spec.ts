import { FindingCategory, FindingSeverity, MalwareArtifactType, MalwareVerdict } from '@prisma/client';
import { AuditService } from '../audit/audit.service';
import { AuthUser } from '../common/interfaces/auth-user.interface';
import { FindingsService } from '../findings/findings.service';
import { PrismaService } from '../prisma/prisma.service';
import { RiskScoresService } from '../risk/risk-scores.service';
import { analyzeEmailArtifact } from './analyzers/email-malware.analyzer';
import { analyzeFileArtifact } from './analyzers/file-malware.analyzer';
import { analyzeUrlArtifact } from './analyzers/url-malware.analyzer';
import { ThreatLabService } from './threat-lab.service';

describe('Threat & Malware Lab — Forensic Analyzers & Service', () => {
  describe('Email Malware & BEC Analyzer', () => {
    it('detects SPF/DMARC failure, Reply-To mismatch, BEC urgency and dangerous double-extension attachment', () => {
      const rawEmail = [
        'From: "Gerencia General CEO" <ceo@empresa-corporativa.co>',
        'Reply-To: cobros-urgentes@atacante-externo.ru',
        'Return-Path: <bounce@mailer-spoof.xyz>',
        'Subject: URGENTE: Transferencia urgente y cambio de cuenta bancaria',
        'Authentication-Results: mx.google.com; spf=fail (google.com: domain of bounce@mailer-spoof.xyz does not designate 185.220.101.5 as permitted sender); dkim=fail; dmarc=fail',
        'Received: from mail.evil-relay.org ([185.220.101.5]) by mx.empresa-corporativa.co',
        'Content-Type: multipart/mixed; boundary="b1"',
        '',
        'Estimado equipo de tesoreria, estoy en reunion confidencial no llamar.',
        'Por favor procesar pago inmediato segun adjunto y verificar en http://185.220.101.5/login-verify',
        'Content-Disposition: attachment; filename="factura_vencida.pdf.exe"',
      ].join('\r\n');

      const res = analyzeEmailArtifact({ rawContent: rawEmail, artifactName: 'bec-sample.eml' });

      expect(res.verdict).toBe(MalwareVerdict.MALICIOUS);
      expect(res.riskScore).toBeGreaterThanOrEqual(80);
      expect(res.severity).toBe(FindingSeverity.CRITICAL);
      expect(res.staticAnalysis.authentication.spf).toBe('fail');
      expect(res.staticAnalysis.authentication.dmarc).toBe('fail');
      expect(res.staticAnalysis.attachments[0]).toMatchObject({
        fileName: 'factura_vencida.pdf.exe',
        dangerousExtension: true,
        doubleExtension: true,
      });
      expect(res.indicators.map((i) => i.code)).toEqual(
        expect.arrayContaining([
          'EMAIL-AUTH-SPOOF-FAIL',
          'EMAIL-REPLY-TO-MISMATCH',
          'EMAIL-BEC-SOCIAL-ENGINEERING',
          'EMAIL-DANGEROUS-ATTACHMENT',
        ]),
      );
    });

    it('marks legitimate authenticated email as CLEAN', () => {
      const cleanEmail = [
        'From: notificaciones@empresa.co',
        'Reply-To: notificaciones@empresa.co',
        'Return-Path: <notificaciones@empresa.co>',
        'Subject: Resumen semanal de actividades del proyecto',
        'Authentication-Results: mx.empresa.co; spf=pass; dkim=pass; dmarc=pass',
        '',
        'Hola equipo, compartimos las notas de la sprint review.',
      ].join('\r\n');

      const res = analyzeEmailArtifact({ rawContent: cleanEmail });

      expect(res.verdict).toBe(MalwareVerdict.CLEAN);
      expect(res.riskScore).toBe(0);
    });
  });

  describe('File & Hash Static Malware Analyzer', () => {
    it('detects EICAR standard test file and known malware hashes via Threat Intel', async () => {
      const res = await analyzeFileArtifact({
        fileName: 'eicar_com.txt',
        rawText: 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*',
      });

      expect(res.verdict).toBe(MalwareVerdict.MALICIOUS);
      expect(res.riskScore).toBeGreaterThanOrEqual(90);
      expect(res.threatIntel.matchedKnownMalware).toBe(true);
      expect(res.threatIntel.malwareFamily).toBe('EICAR-Test-File');
    });

    it('detects PE executable masquerading as a PDF document (Magic Bytes mismatch + double extension)', async () => {
      // MZ header (0x4D 0x5A) + suspicious strings inside a file named .pdf
      const fakePdfBuffer = Buffer.concat([
        Buffer.from([0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00]),
        Buffer.from('VirtualAlloc WriteProcessMemory CreateRemoteThread FromBase64String -EncodedCommand', 'ascii'),
      ]);

      const res = await analyzeFileArtifact({
        fileName: 'orden_de_compra.pdf',
        mimeType: 'application/pdf',
        contentBase64: fakePdfBuffer.toString('base64'),
      });

      expect(res.verdict).toBe(MalwareVerdict.MALICIOUS);
      expect(res.staticAnalysis.extensionMismatch).toBe(true);
      expect(res.staticAnalysis.detectedMagicFormat).toContain('PE_EXECUTABLE');
      expect(res.indicators.map((i) => i.code)).toEqual(
        expect.arrayContaining([
          'FILE-MAGIC-BYTES-MASQUERADING',
          'FILE-SUSPICIOUS-EXECUTION-PATTERNS',
        ]),
      );
    });

    it('detects dangerous PDF dictionary objects (/JS, /Launch, /OpenAction)', async () => {
      const pdfWithJs = '%PDF-1.7\n1 0 obj << /Type /Catalog /OpenAction << /S /JavaScript /JS (app.launchURL("http://evil.local")) >> /Launch >> endobj';
      const res = await analyzeFileArtifact({
        fileName: 'estado_cuenta.pdf',
        rawText: pdfWithJs,
      });

      expect(res.staticAnalysis.pdfDangerousActions).toEqual(
        expect.arrayContaining(['/JS', '/JavaScript', '/Launch', '/OpenAction']),
      );
      expect(res.verdict).toBe(MalwareVerdict.SUSPICIOUS);
    });
  });

  describe('URL Phishing & Malware Delivery Analyzer', () => {
    it('detects brand impersonation, high-abuse TLD and credential harvesting path', () => {
      const res = analyzeUrlArtifact({
        url: 'http://sucursal-bancol0mbia-personas.top/secure-login/verify?token=1',
      });

      expect(res.verdict).toBe(MalwareVerdict.MALICIOUS);
      expect(res.staticAnalysis.impersonatedBrand).toBe('Bancolombia');
      expect(res.staticAnalysis.suspiciousTld).toBe(true);
      expect(res.threatIntel.threatCategory).toBe('PHISHING');
    });

    it('detects literal IP hosting direct executable payload (.exe)', () => {
      const res = analyzeUrlArtifact({
        url: 'http://45.133.1.99:8088/bins/loader_x86.exe',
      });

      expect(res.verdict).toBe(MalwareVerdict.MALICIOUS);
      expect(res.staticAnalysis.usesLiteralIp).toBe(true);
      expect(res.staticAnalysis.directPayloadExtension).toBe('exe');
      expect(res.threatIntel.threatCategory).toBe('MALWARE_DISTRIBUTION');
    });
  });

  describe('ThreatLabService — persistence & promotion to unified Finding', () => {
    let service: ThreatLabService;
    let prismaMock: {
      asset: { findFirst: jest.Mock };
      user: { findFirst: jest.Mock };
      malwareAnalysis: {
        create: jest.Mock;
        findFirst: jest.Mock;
        findMany: jest.Mock;
        count: jest.Mock;
        groupBy: jest.Mock;
        update: jest.Mock;
      };
      finding: {
        findUnique: jest.Mock;
        create: jest.Mock;
        update: jest.Mock;
      };
      $transaction: jest.Mock;
    };
    let findingsServiceMock: { findOne: jest.Mock };
    let riskScoresMock: { snapshot: jest.Mock };
    let auditMock: { record: jest.Mock };

    const actor: AuthUser = {
      id: 'u-analyst',
      organizationId: 'org-1',
      role: 'ANALYST',
      fullName: 'SOC Analyst',
      email: 'soc@empresa.co',
    };

    beforeEach(() => {
      prismaMock = {
        asset: { findFirst: jest.fn() },
        user: { findFirst: jest.fn() },
        malwareAnalysis: {
          create: jest.fn(),
          findFirst: jest.fn(),
          findMany: jest.fn(),
          count: jest.fn(),
          groupBy: jest.fn(),
          update: jest.fn(),
        },
        finding: {
          findUnique: jest.fn(),
          create: jest.fn(),
          update: jest.fn(),
        },
        $transaction: jest.fn(async (cb) =>
          typeof cb === 'function' ? cb(prismaMock) : Promise.all(cb),
        ),
      };
      findingsServiceMock = {
        findOne: jest.fn(),
      };
      riskScoresMock = {
        snapshot: jest.fn().mockResolvedValue(undefined),
      };
      auditMock = {
        record: jest.fn(),
      };

      service = new ThreatLabService(
        prismaMock as unknown as PrismaService,
        findingsServiceMock as unknown as FindingsService,
        riskScoresMock as unknown as RiskScoresService,
        auditMock as unknown as AuditService,
      );
    });

    it('promotes a malicious URL analysis to a formal MALWARE_THREAT finding and snapshots asset score', async () => {
      prismaMock.malwareAnalysis.findFirst.mockResolvedValueOnce({
        id: 'ma-1',
        organizationId: 'org-1',
        artifactType: MalwareArtifactType.URL,
        artifactName: 'http://bancol0mbia-login.top/verify',
        verdict: MalwareVerdict.MALICIOUS,
        riskScore: 85,
        severity: FindingSeverity.CRITICAL,
        summary: 'URL maliciosa de phishing bancario',
        sha256: 'abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234',
        md5: '1234',
        sha1: '5678',
        staticAnalysis: {},
        threatIntel: { threatCategory: 'PHISHING' },
        indicators: [],
        recommendations: ['Bloquear dominio en DNS'],
      });
      prismaMock.asset.findFirst.mockResolvedValueOnce({
        id: 'asset-1',
        name: 'Portal Principal',
        value: 'empresa.co',
      });
      prismaMock.finding.findUnique.mockResolvedValueOnce(null);
      prismaMock.finding.create.mockResolvedValueOnce({
        id: 'finding-promoted-1',
      });
      prismaMock.malwareAnalysis.update.mockResolvedValueOnce({
        id: 'ma-1',
        promotedFindingId: 'finding-promoted-1',
      });
      findingsServiceMock.findOne.mockResolvedValueOnce({
        id: 'finding-promoted-1',
        ruleId: 'THREAT-URL-MALICIOUS-PHISHING',
        category: FindingCategory.MALWARE_THREAT,
        sourceType: 'THREAT_MALWARE_LAB',
      });

      const res = await service.promoteToFinding(actor, 'ma-1', {
        assetId: 'asset-1',
      });

      expect(prismaMock.finding.create).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            organizationId: 'org-1',
            assetId: 'asset-1',
            category: FindingCategory.MALWARE_THREAT,
            ruleId: 'THREAT-URL-MALICIOUS-PHISHING',
            severity: FindingSeverity.CRITICAL,
          }),
        }),
      );
      expect(riskScoresMock.snapshot).toHaveBeenCalledTimes(1);
      expect(auditMock.record).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'threat_lab.promote_finding',
          organizationId: 'org-1',
        }),
      );
      expect(res.finding.id).toBe('finding-promoted-1');
    });
  });
});
