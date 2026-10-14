import { NotFoundException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../prisma/prisma.service';
import { FindingTriageService } from './finding-triage.service';

describe('FindingTriageService', () => {
  let service: FindingTriageService;
  let prismaMock: {
    finding: {
      findFirst: jest.Mock;
    };
  };
  let configMock: {
    get: jest.Mock;
  };

  const baseFinding = {
    id: 'f-1',
    organizationId: 'org-1',
    ruleId: 'HDR-CSP-MISSING',
    category: 'HTTP_HEADERS',
    severity: 'MEDIUM',
    cvssScore: 4.5,
    title: 'Falta cabecera Content-Security-Policy',
    description: 'La cabecera CSP no está presente',
    location: 'https://api.empresa.com/v1/auth',
    evidence: { contentType: 'application/json' },
    asset: {
      id: 'a-1',
      type: 'DOMAIN',
      value: 'api.empresa.com',
      name: 'API Gateway',
      criticality: 'HIGH',
      tags: ['api', 'production'],
    },
  };

  beforeEach(() => {
    prismaMock = {
      finding: {
        findFirst: jest.fn(),
      },
    };

    configMock = {
      get: jest.fn((key: string) => {
        if (key === 'AI_API_KEY') return undefined; // por defecto sin LLM
        return undefined;
      }),
    };

    service = new FindingTriageService(
      prismaMock as unknown as PrismaService,
      configMock as unknown as ConfigService,
    );
  });

  it('lanza NotFoundException si el hallazgo no existe', async () => {
    prismaMock.finding.findFirst.mockResolvedValueOnce(null);
    await expect(service.analyze('org-1', 'f-999')).rejects.toThrow(NotFoundException);
  });

  it('detecta probable falso positivo para CSP faltante en un activo tipo API', async () => {
    prismaMock.finding.findFirst.mockResolvedValueOnce(baseFinding);

    const result = await service.analyze('org-1', 'f-1');

    expect(result.findingId).toBe('f-1');
    expect(result.verdict).toBe('PROBABLE_FALSE_POSITIVE');
    expect(result.confidence).toBe('HIGH');
    expect(result.recommendedAction).toBe('MARK_FALSE_POSITIVE');
    expect(result.provider).toBe('heuristic-expert');
    expect(result.summary).toContain('falso positivo');
    expect(result.contextFactors.length).toBeGreaterThan(0);
    expect(result.suggestedNote).toContain('Falso positivo confirmado');
  });

  it('detecta probable falso positivo para SPF reportado sobre una dirección IP', async () => {
    prismaMock.finding.findFirst.mockResolvedValueOnce({
      ...baseFinding,
      id: 'f-2',
      ruleId: 'EMAIL-SPF-MISSING',
      category: 'EMAIL_SECURITY',
      location: '198.51.100.4',
      asset: {
        id: 'a-2',
        type: 'IP',
        value: '198.51.100.4',
        name: 'Servidor Web',
        tags: [],
      },
    });

    const result = await service.analyze('org-1', 'f-2');

    expect(result.verdict).toBe('PROBABLE_FALSE_POSITIVE');
    expect(result.recommendedAction).toBe('MARK_FALSE_POSITIVE');
    expect(result.summary).toContain('SPF/DMARC');
  });

  it('confirma riesgo verdadero para fugas críticas (.env o git)', async () => {
    prismaMock.finding.findFirst.mockResolvedValueOnce({
      ...baseFinding,
      id: 'f-3',
      ruleId: 'PATH-ENV-FILE',
      category: 'SENSITIVE_PATH',
      severity: 'CRITICAL',
      title: 'Archivo .env expuesto',
      location: 'https://api.empresa.com/.env',
    });

    const result = await service.analyze('org-1', 'f-3');

    expect(result.verdict).toBe('CONFIRMED_TRUE_POSITIVE');
    expect(result.confidence).toBe('HIGH');
    expect(result.recommendedAction).toBe('REMEDIATE');
  });

  it('confirma riesgo verdadero para base de datos expuesta', async () => {
    prismaMock.finding.findFirst.mockResolvedValueOnce({
      ...baseFinding,
      id: 'f-4',
      ruleId: 'SVC-DATABASE-EXPOSED',
      category: 'EXPOSED_SERVICE',
      severity: 'HIGH',
      location: 'tcp/5432',
      title: 'PostgreSQL expuesto',
    });

    const result = await service.analyze('org-1', 'f-4');

    expect(result.verdict).toBe('CONFIRMED_TRUE_POSITIVE');
    expect(result.recommendedAction).toBe('REMEDIATE');
  });

  it('utiliza la memoria caché y no vuelve a consultar a la BD hasta que se fuerce el refresco', async () => {
    prismaMock.finding.findFirst.mockResolvedValueOnce(baseFinding);

    const first = await service.analyze('org-1', 'f-1');
    expect(prismaMock.finding.findFirst).toHaveBeenCalledTimes(1);

    const cached = await service.analyze('org-1', 'f-1');
    expect(prismaMock.finding.findFirst).toHaveBeenCalledTimes(1);
    expect(cached).toEqual(first);

    prismaMock.finding.findFirst.mockResolvedValueOnce(baseFinding);
    const refreshed = await service.analyze('org-1', 'f-1', true);
    expect(prismaMock.finding.findFirst).toHaveBeenCalledTimes(2);
    expect(refreshed.findingId).toBe('f-1');
  });

  it('genera análisis con IA cuando AI_API_KEY está configurada', async () => {
    configMock.get.mockImplementation((key: string) => {
      if (key === 'AI_API_KEY') return 'sk-test-key';
      if (key === 'AI_API_URL') return 'https://api.openai.com/v1';
      if (key === 'AI_MODEL') return 'gpt-4o-mini';
      return undefined;
    });

    prismaMock.finding.findFirst.mockResolvedValueOnce(baseFinding);

    const mockAiResponse = {
      verdict: 'PROBABLE_FALSE_POSITIVE',
      confidence: 'HIGH',
      confidenceScore: 90,
      summary: 'Falso positivo confirmado por IA debido a arquitectura de microservicio.',
      reasoning: ['Las cabeceras CSP aplican a documentos HTML navegables.'],
      contextFactors: [{ factor: 'Arquitectura Headless', impact: 'INCREASES_FP_PROBABILITY', detail: 'Sin renderizado HTML' }],
      recommendedAction: 'MARK_FALSE_POSITIVE',
      suggestedNote: 'Falso positivo según análisis contextual de microservicio.',
    };

    const originalFetch = global.fetch;
    global.fetch = jest.fn().mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        choices: [{ message: { content: JSON.stringify(mockAiResponse) } }],
      }),
    } as unknown as Response);

    try {
      const result = await service.analyze('org-1', 'f-ai-1', true);
      expect(result.provider).toBe('ai');
      expect(result.summary).toBe(mockAiResponse.summary);
      expect(result.confidenceScore).toBe(90);
    } finally {
      global.fetch = originalFetch;
    }
  });

  it('hace fallback transparente al motor heurístico si la llamada a la IA falla', async () => {
    configMock.get.mockImplementation((key: string) => {
      if (key === 'AI_API_KEY') return 'sk-test-key';
      return undefined;
    });

    prismaMock.finding.findFirst.mockResolvedValueOnce(baseFinding);

    const originalFetch = global.fetch;
    global.fetch = jest.fn().mockRejectedValueOnce(new Error('Network connection error'));

    try {
      const result = await service.analyze('org-1', 'f-ai-fallback', true);
      expect(result.provider).toBe('heuristic-expert');
      expect(result.verdict).toBe('PROBABLE_FALSE_POSITIVE');
    } finally {
      global.fetch = originalFetch;
    }
  });
});
