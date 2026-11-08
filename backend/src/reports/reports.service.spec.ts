import { FindingCategory, FindingSeverity, FindingStatus, ReportType, ScanType } from '@prisma/client';
import { ReportsService } from './reports.service';

describe('ReportsService', () => {
  let service: ReportsService;
  let prismaMock: any;
  let riskScoresMock: any;
  let attackPathsMock: any;

  beforeEach(() => {
    prismaMock = {
      organization: {
        findUniqueOrThrow: jest.fn().mockResolvedValue({ name: 'Tienda Online S.A.' }),
      },
      asset: {
        findFirst: jest.fn(),
        findMany: jest.fn().mockResolvedValue([
          {
            id: 'asset-1',
            type: 'DOMAIN',
            value: 'tienda.com',
            name: 'Portal E-Commerce',
            isActive: true,
            lastScannedAt: new Date(),
            findings: [
              {
                id: 'f-1',
                ruleId: 'HDR-CSP-MISSING',
                category: FindingCategory.HTTP_HEADERS,
                severity: FindingSeverity.MEDIUM,
                cvssScore: 5.3,
                status: FindingStatus.OPEN,
                title: 'Cabecera Content-Security-Policy ausente',
                description: 'La cabecera no se encuentra configurada',
                recommendation: 'Configure CSP restrictiva',
                location: 'https://tienda.com',
                evidence: null,
                firstSeenAt: new Date(),
                lastSeenAt: new Date(),
              },
              {
                id: 'f-2',
                ruleId: 'MAIL-DMARC-MISSING',
                category: FindingCategory.EMAIL_SECURITY,
                severity: FindingSeverity.HIGH,
                cvssScore: 7.5,
                status: FindingStatus.OPEN,
                title: 'Registro DMARC no configurado',
                description: 'Permite suplantación de correo',
                recommendation: 'Publique registro DMARC',
                location: 'tienda.com',
                evidence: null,
                firstSeenAt: new Date(),
                lastSeenAt: new Date(),
              },
            ],
            scans: [
              { type: ScanType.WEB_HEADERS, finishedAt: new Date() },
            ],
          },
        ]),
      },
      scan: {
        findFirst: jest.fn().mockResolvedValue(null),
      },
      alert: {
        count: jest.fn().mockResolvedValue(0),
      },
      report: {
        create: jest.fn().mockResolvedValue({ id: 'rep-1' }),
      },
      malwareAnalysis: {
        findMany: jest.fn().mockResolvedValue([
          {
            artifactType: 'EMAIL',
            artifactName: 'phishing_factura.eml',
            verdict: 'MALICIOUS',
            riskScore: 92,
            promotedFindingId: 'f-2',
            createdAt: new Date(),
          },
        ]),
      },
      diagnosticBatch: {
        count: jest.fn().mockResolvedValue(2),
        findFirst: jest.fn().mockResolvedValue({
          status: 'COMPLETED',
          profile: 'COMMERCE_360',
          summary: { deltaScore: 8, remediatedFindingsCount: 3, regressionsCount: 0 },
        }),
      },
    };

    riskScoresMock = {
      current: jest.fn().mockResolvedValue({
        score: 75,
        grade: 'C',
        label: 'Aceptable',
        description: 'Postura intermedia',
        counts: { CRITICAL: 0, HIGH: 1, MEDIUM: 1, LOW: 0, INFO: 0 },
        scoredAssets: 1,
        totalAssets: 1,
      }),
      latestBefore: jest.fn().mockResolvedValue(null),
      history: jest.fn().mockResolvedValue({ points: [] }),
    };

    attackPathsMock = {
      analyzeAttackPaths: jest.fn().mockResolvedValue([
        {
          id: 'AP-BRAND-IMPERSONATION',
          title: 'Suplantación de Marca y Fraude Facturero (BEC / Phishing)',
          category: 'BRAND_IMPERSONATION',
          severity: 'HIGH',
          narrative: 'Riesgo de fraude por correo',
          businessRisk: 'Desvío de pagos de clientes',
          estimatedImpact: 'Alto impacto financiero',
          assetValue: 'tienda.com',
          killChainSteps: [],
          activeFindings: [],
          quickWinsAvailable: 1,
          remediationEffort: 'QUICK_WIN',
          recommendedActions: ['Configurar DMARC con p=quarantine'],
        },
      ]),
    };

    service = new ReportsService(prismaMock, riskScoresMock, attackPathsMock);
  });

  it('gather populates attackPaths and quickWins for executive report', async () => {
    const actor: any = { id: 'u-1', fullName: 'Carlos Admin', organizationId: 'org-1' };
    const reportData = await service.gather(actor, ReportType.EXECUTIVE);

    expect(reportData.attackPaths).toHaveLength(1);
    expect(reportData.attackPaths?.[0].id).toBe('AP-BRAND-IMPERSONATION');
    expect(reportData.quickWins).toBeDefined();
    expect(reportData.quickWins?.length).toBeGreaterThanOrEqual(1);
    expect(reportData.quickWins?.some((qw) => qw.ruleId === 'MAIL-DMARC-MISSING')).toBe(true);
    expect(reportData.threatLabSummary).toMatchObject({
      total: 1,
      malicious: 1,
      promotedCount: 1,
    });
    expect(reportData.diagnostic360Summary).toMatchObject({
      totalBatches: 2,
      latestProfile: 'COMMERCE_360',
      deltaScore: 8,
    });
  });

  it('generate produces a valid PDF buffer including attack paths and quick wins', async () => {
    const actor: any = { id: 'u-1', fullName: 'Carlos Admin', organizationId: 'org-1' };
    const result = await service.generate(actor, ReportType.EXECUTIVE);

    expect(result.filename).toMatch(/^sspm-reporte-ejecutivo-tienda-online-s-a-\d{8}\.pdf$/);
    expect(result.buffer).toBeInstanceOf(Buffer);
    expect(result.buffer.subarray(0, 5).toString()).toBe('%PDF-');
    expect(prismaMock.report.create).toHaveBeenCalled();
  });
});
