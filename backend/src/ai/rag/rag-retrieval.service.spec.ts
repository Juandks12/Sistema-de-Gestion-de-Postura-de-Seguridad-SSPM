import { NotFoundException } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';
import { EmbeddingService } from '../embeddings/embedding.service';
import { RagRetrievalService } from './rag-retrieval.service';
import { KnowledgeCategoryEnum } from './dto/rag-search.dto';

describe('RagRetrievalService', () => {
  let service: RagRetrievalService;
  let prisma: {
    $queryRawUnsafe: jest.Mock;
    finding: { findFirst: jest.Mock };
  };
  let embeddingService: {
    generateEmbedding: jest.Mock;
  };

  beforeEach(() => {
    prisma = {
      $queryRawUnsafe: jest.fn(),
      finding: { findFirst: jest.fn() },
    };

    embeddingService = {
      generateEmbedding: jest.fn().mockResolvedValue(new Array(1536).fill(0.01)),
    };

    service = new RagRetrievalService(
      prisma as unknown as PrismaService,
      embeddingService as unknown as EmbeddingService,
    );
  });

  it('debe ejecutar una búsqueda semántica usando el operador de distancia coseno de pgvector', async () => {
    const mockResults = [
      {
        id: '123e4567-e89b-12d3-a456-426614174000',
        category: 'HARDENING_GUIDE',
        sourceId: 'GUIDE-HDR-HSTS',
        title: 'Bastionado HSTS',
        content: 'Configuración HSTS',
        metadata: { technology: 'Nginx' },
        similarity: 0.88,
      },
    ];

    prisma.$queryRawUnsafe.mockResolvedValue(mockResults);

    const res = await service.searchSemantic({
      query: 'HSTS bastionado',
      category: KnowledgeCategoryEnum.HARDENING_GUIDE,
      limit: 5,
    });

    expect(embeddingService.generateEmbedding).toHaveBeenCalledWith('HSTS bastionado');
    expect(prisma.$queryRawUnsafe).toHaveBeenCalled();
    expect(res).toHaveLength(1);
    expect(res[0].sourceId).toBe('GUIDE-HDR-HSTS');
    expect(res[0].similarity).toBe(0.88);
  });

  it('debe lanzar NotFoundException si el hallazgo no existe al generar remediación', async () => {
    prisma.finding.findFirst.mockResolvedValue(null);

    await expect(
      service.generateRemediationAdvice('missing-id', 'org-1'),
    ).rejects.toThrow(NotFoundException);
  });

  it('debe generar un playbook de remediación grounded y estructurado', async () => {
    const mockFinding = {
      id: 'f-1',
      organizationId: 'org-1',
      assetId: 'asset-1',
      ruleId: 'HDR-HSTS-MISSING',
      category: 'WEB_HEADERS',
      severity: 'HIGH',
      cvssScore: 7.5,
      title: 'Cabecera Strict-Transport-Security no implementada',
      description: 'El servidor no envía la cabecera HSTS.',
      recommendation: 'Agregar la cabecera HSTS.',
      location: 'https://example.com/',
      asset: { id: 'asset-1', value: 'example.com', type: 'DOMAIN' },
    };

    prisma.finding.findFirst.mockResolvedValue(mockFinding);
    prisma.$queryRawUnsafe.mockResolvedValue([
      {
        id: 'k-1',
        category: 'REMEDIATION_IAC',
        sourceId: 'IAC-GUIDE-HDR-HSTS',
        title: 'Nginx HSTS Config',
        content: '```nginx\nadd_header Strict-Transport-Security "max-age=31536000";\n```',
        metadata: { format: 'nginx' },
        similarity: 0.92,
      },
      {
        id: 'k-2',
        category: 'GRC_CONTROL',
        sourceId: 'GRC-ISO_27001-A.8.20',
        title: '[ISO_27001] Seguridad de Red',
        content: 'Control A.8.20',
        metadata: { framework: 'ISO_27001', code: 'A.8.20' },
        similarity: 0.85,
      },
    ]);

    const playbook = await service.generateRemediationAdvice('f-1', 'org-1');

    expect(playbook.findingId).toBe('f-1');
    expect(playbook.ruleId).toBe('HDR-HSTS-MISSING');
    expect(playbook.stepByStepRemediation.length).toBeGreaterThan(0);
    expect(playbook.codeSnippets.length).toBeGreaterThan(0);
    expect(playbook.codeSnippets[0].language).toBe('nginx');
    expect(playbook.verificationTest.command).toContain('curl');
    expect(playbook.complianceImpact.length).toBeGreaterThan(0);
    expect(playbook.groundedCitations.length).toBeGreaterThan(0);
  });
});
