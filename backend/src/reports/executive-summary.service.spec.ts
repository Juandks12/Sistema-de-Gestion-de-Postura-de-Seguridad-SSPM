import { ConfigService } from '@nestjs/config';
import { FindingCategory, FindingSeverity, ReportType } from '@prisma/client';
import { AuthUser } from '../common/interfaces/auth-user.interface';
import { ExecutiveSummaryService } from './executive-summary.service';
import { ReportData } from './report-data';
import { ReportsService } from './reports.service';

describe('ExecutiveSummaryService', () => {
  let service: ExecutiveSummaryService;
  let reportsMock: { gather: jest.Mock };
  let configMock: { get: jest.Mock };

  const actor: AuthUser = {
    id: 'user-1',
    organizationId: 'org-1',
    email: 'admin@test.local',
    role: 'ADMIN',
    fullName: 'Admin Test',
  };

  const sampleReportData: ReportData = {
    type: ReportType.EXECUTIVE,
    generatedAt: new Date(),
    generatedBy: 'Admin Test',
    organizationName: 'Empresa Demo SAS',
    scope: { kind: 'ORGANIZATION' },
    score: {
      score: 45,
      grade: 'D',
      label: 'Deficiente',
      description: 'Postura con penalizaciones graves.',
      counts: {
        CRITICAL: 1,
        HIGH: 2,
        MEDIUM: 3,
        LOW: 1,
        INFO: 0,
      },
      scoredAssets: 2,
      totalAssets: 2,
      weekAgoScore: 60,
    },
    history: [{ date: new Date(), score: 45 }],
    assets: [
      {
        id: 'asset-1',
        type: 'DOMAIN',
        value: 'api.demo.com',
        name: 'API Gateway',
        isActive: true,
        scored: true,
        score: 40,
        grade: 'D',
        counts: { CRITICAL: 1, HIGH: 1, MEDIUM: 2, LOW: 1, INFO: 0 },
        lastScannedAt: new Date(),
        lastScanByType: {},
        openPorts: [{ port: 5432, protocol: 'tcp', serviceName: 'postgresql', product: 'PostgreSQL', version: '15' }],
        portScanAt: new Date(),
        findings: [
          {
            id: 'f-1',
            ruleId: 'API-ACTUATOR-ENV-EXPOSED',
            category: FindingCategory.SENSITIVE_PATH,
            severity: FindingSeverity.CRITICAL,
            cvssScore: 9.8,
            title: 'Endpoints de telemetría expuestos',
            description: 'Acceso a variables de entorno',
            recommendation: 'Restringir actuator',
            location: 'https://api.demo.com/actuator/env',
            evidence: { kev: true },
            firstSeenAt: new Date(),
            lastSeenAt: new Date(),
          },
          {
            id: 'f-2',
            ruleId: 'HDR-EOL-TECH',
            category: FindingCategory.HTTP_HEADERS,
            severity: FindingSeverity.HIGH,
            cvssScore: 7.5,
            title: 'Tecnología EOL detectada',
            description: 'PHP 7.4 sin soporte',
            recommendation: 'Migrar a versión soportada',
            location: 'https://api.demo.com',
            evidence: null,
            firstSeenAt: new Date(),
            lastSeenAt: new Date(),
          },
        ],
        excluded: { accepted: 0, falsePositive: 0 },
      },
      {
        id: 'asset-2',
        type: 'DOMAIN',
        value: 'demo.com',
        name: 'Sitio Web',
        isActive: true,
        scored: true,
        score: 50,
        grade: 'C',
        counts: { CRITICAL: 0, HIGH: 1, MEDIUM: 1, LOW: 0, INFO: 0 },
        lastScannedAt: new Date(),
        lastScanByType: {},
        openPorts: [{ port: 443, protocol: 'tcp', serviceName: 'https', product: 'nginx', version: null }],
        portScanAt: new Date(),
        findings: [
          {
            id: 'f-3',
            ruleId: 'DNS-DMARC-MISSING',
            category: FindingCategory.EMAIL_SECURITY,
            severity: FindingSeverity.HIGH,
            cvssScore: 7.5,
            title: 'DMARC no configurado',
            description: 'Dominio vulnerable a spoofing',
            recommendation: 'Crear registro DMARC',
            location: 'demo.com',
            evidence: null,
            firstSeenAt: new Date(),
            lastSeenAt: new Date(),
          },
        ],
        excluded: { accepted: 0, falsePositive: 0 },
      },
    ],
    alerts: { last30Days: 4, unacknowledged: 1 },
  };

  beforeEach(() => {
    reportsMock = {
      gather: jest.fn().mockResolvedValue(sampleReportData),
    };
    configMock = {
      get: jest.fn().mockReturnValue(undefined),
    };
    service = new ExecutiveSummaryService(reportsMock as unknown as ReportsService, configMock as unknown as ConfigService);
  });

  describe('generateHeuristicSummary', () => {
    it('determina nivel de riesgo CRÍTICO ante hallazgos críticos y score bajo', () => {
      const result = service.generateHeuristicSummary(sampleReportData);

      expect(result.riskLevel).toBe('CRÍTICO');
      expect(result.headline).toContain('Postura crítica');
      expect(result.scoreOverview.score).toBe(45);
      expect(result.scoreOverview.grade).toBe('D');
      expect(result.scoreOverview.trendLabel).toContain('deterioro significativo');
    });

    it('genera análisis de impacto en negocio en las 4 dimensiones requeridas', () => {
      const result = service.generateHeuristicSummary(sampleReportData);

      expect(result.businessImpacts).toHaveLength(4);
      const areas = result.businessImpacts.map((b) => b.area);
      expect(areas).toEqual(['Operativa', 'Financiera', 'Regulatoria/Legal', 'Reputacional']);

      const op = result.businessImpacts.find((b) => b.area === 'Operativa')!;
      expect(op.description).toMatch(/ransomware|secuestro|bases de datos/i);

      const fin = result.businessImpacts.find((b) => b.area === 'Financiera')!;
      expect(fin.description).toMatch(/credenciales|remediación|exfiltración/i);

      const reg = result.businessImpacts.find((b) => b.area === 'Regulatoria/Legal')!;
      expect(reg.description).toMatch(/Habeas Data|RGPD|protección de datos/i);

      const rep = result.businessImpacts.find((b) => b.area === 'Reputacional')!;
      expect(rep.description).toMatch(/phishing|suplantación/i);
    });

    it('genera las 3 acciones estratégicas prioritarias ordenadas', () => {
      const result = service.generateHeuristicSummary(sampleReportData);

      expect(result.topPriorities).toHaveLength(3);
      expect(result.topPriorities[0].order).toBe(1);
      expect(result.topPriorities[0].title).toBe('Aislamiento Perimetral Inmediato');
      expect(result.topPriorities[0].businessJustification).toBeDefined();

      expect(result.topPriorities[1].order).toBe(2);
      expect(result.topPriorities[1].title).toBe('Plan de Parcheo de Vulnerabilidades Críticas');

      expect(result.topPriorities[2].order).toBe(3);
      expect(result.topPriorities[2].title).toBe('Blindaje de Identidad de Correo y Dominio');
    });

    it('incluye advertencia de deuda técnica para software EOL y puertos de base de datos', () => {
      const result = service.generateHeuristicSummary(sampleReportData);

      expect(result.technicalDebtSummary).toBeDefined();
      expect(result.technicalDebtSummary).toContain('fin de ciclo');
    });

    it('maneja organizaciones sin hallazgos abiertos con postura sólida y riesgo BAJO', () => {
      const cleanData: ReportData = {
        ...sampleReportData,
        score: {
          ...sampleReportData.score,
          score: 95,
          grade: 'A',
          label: 'Excelente',
          description: 'Sin problemas detectados.',
          counts: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
          weekAgoScore: 95,
        },
        assets: [
          {
            ...sampleReportData.assets[0],
            openPorts: [{ port: 443, protocol: 'tcp', serviceName: 'https', product: 'nginx', version: '1.24' }],
            findings: [],
          },
        ],
      };

      const result = service.generateHeuristicSummary(cleanData);

      expect(result.riskLevel).toBe('BAJO');
      expect(result.headline).toContain('Postura sólida');
      expect(result.scoreOverview.trendLabel).toBe('Estable');
      expect(result.businessImpacts.every((b) => b.severity === 'BAJO')).toBe(true);
    });
  });

  describe('getSummary y caché', () => {
    it('utiliza caché en memoria para llamadas subsecuentes con la misma organización', async () => {
      const first = await service.getSummary(actor);
      const second = await service.getSummary(actor);

      expect(first).toBe(second);
      expect(reportsMock.gather).toHaveBeenCalledTimes(1);
    });

    it('recalcula y actualiza caché si forceRefresh es true', async () => {
      await service.getSummary(actor);
      await service.getSummary(actor, undefined, true);

      expect(reportsMock.gather).toHaveBeenCalledTimes(2);
    });

    it('hace fallback seguro al motor heurístico si la llamada a IA arroja error', async () => {
      configMock.get.mockImplementation((key: string) => {
        if (key === 'AI_API_KEY') return 'sk-test-key';
        return undefined;
      });

      // Simular fallo en fetch global
      const originalFetch = global.fetch;
      global.fetch = jest.fn().mockRejectedValueOnce(new Error('Network connection error'));

      try {
        const result = await service.getSummary(actor);
        expect(result.provider).toBe('heuristic-expert');
        expect(result.riskLevel).toBe('CRÍTICO');
      } finally {
        global.fetch = originalFetch;
      }
    });
  });
});
