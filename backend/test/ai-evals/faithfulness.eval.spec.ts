import { OutputGuardrailService } from '../../src/ai/guardrails/output-guardrail.service';
import { PromptInjectionShieldService } from '../../src/ai/guardrails/prompt-injection-shield.service';
import { RagRetrievalService } from '../../src/ai/rag/rag-retrieval.service';
import { EmbeddingService } from '../../src/ai/embeddings/embedding.service';
import { PrismaService } from '../../src/prisma/prisma.service';

describe('AI Evaluation: RAG Grounding & Faithfulness Suite', () => {
  let ragService: RagRetrievalService;
  let guardrailService: OutputGuardrailService;
  let prismaMock: {
    finding: { findFirst: jest.Mock };
    $queryRawUnsafe: jest.Mock;
  };
  let embeddingServiceMock: {
    generateEmbedding: jest.Mock;
  };

  const VALID_FRAMEWORKS = new Set(['CIS', 'NIST', 'ISO 27001', 'PCI-DSS', 'SOC 2', 'HIPAA', 'GDPR', 'GRC']);

  beforeEach(() => {
    prismaMock = {
      finding: { findFirst: jest.fn() },
      $queryRawUnsafe: jest.fn(),
    };
    embeddingServiceMock = {
      generateEmbedding: jest.fn().mockResolvedValue(new Array(1536).fill(0.01)),
    };
    guardrailService = new OutputGuardrailService();

    ragService = new RagRetrievalService(
      prismaMock as unknown as PrismaService,
      embeddingServiceMock as unknown as EmbeddingService,
      new PromptInjectionShieldService(),
      guardrailService,
    );
  });

  it('generates 100% grounded playbooks without hallucinated compliance framework codes', async () => {
    prismaMock.finding.findFirst.mockResolvedValueOnce({
      id: 'f-hsts',
      ruleId: 'HDR-HSTS-MISSING',
      title: 'Cabecera Strict-Transport-Security no configurada',
      category: 'HTTP_HEADERS',
      severity: 'HIGH',
      location: 'https://banca.empresa.com',
      recommendation: 'Habilitar directiva Strict-Transport-Security con max-age >= 31536000.',
      assetId: 'a-1',
      asset: { id: 'a-1', value: 'banca.empresa.com', type: 'WEB_APPLICATION' },
    });

    // Mock pgvector semantic retrieval results
    prismaMock.$queryRawUnsafe
      .mockResolvedValueOnce([
        {
          id: 'iac-1',
          category: 'REMEDIATION_IAC',
          sourceId: 'IAC-NGINX-HSTS',
          title: 'Configuración segura HSTS en Nginx',
          content: '```nginx\nadd_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;\n```',
          metadata: { format: 'nginx' },
          similarity: 0.88,
        },
      ])
      .mockResolvedValueOnce([
        {
          id: 'guide-1',
          category: 'HARDENING_GUIDE',
          sourceId: 'GUIDE-TLS-HSTS',
          title: 'Guía de Hardening Perimetral TLS y HSTS',
          content: 'HSTS previene ataques de Man-in-the-Middle y SSL-Stripping forzando HTTPS en todo momento.',
          metadata: {},
          similarity: 0.82,
        },
      ])
      .mockResolvedValueOnce([
        {
          id: 'ctrl-1',
          category: 'GRC_CONTROL',
          sourceId: 'PCI-DSS-4.1',
          title: 'Cifrado de datos en tránsito sobre redes públicas',
          content: 'Requisito 4.1 de PCI-DSS exige criptografía fuerte para proteger datos de titulares de tarjetas.',
          metadata: { framework: 'PCI-DSS', code: '4.1' },
          similarity: 0.79,
        },
        {
          id: 'ctrl-2',
          category: 'GRC_CONTROL',
          sourceId: 'NIST-SC-8',
          title: 'Transmisión confidencial e íntegra',
          content: 'NIST SP 800-53 Control SC-8.',
          metadata: { framework: 'NIST', code: 'SC-8' },
          similarity: 0.75,
        },
      ])
      .mockResolvedValueOnce([]);

    const playbook = await ragService.generateRemediationAdvice('f-hsts', 'org-1');

    // 1. Validar grounding de citaciones
    expect(playbook.groundedCitations.length).toBeGreaterThanOrEqual(3);
    for (const citation of playbook.groundedCitations) {
      expect(citation.similarityScore).toBeGreaterThanOrEqual(0.05);
      expect(citation.title).toBeDefined();
    }

    // 2. Validar que no hay frameworks inventados ni alucinaciones
    expect(playbook.complianceImpact.length).toBe(2);
    for (const comp of playbook.complianceImpact) {
      expect(VALID_FRAMEWORKS.has(comp.framework)).toBe(true);
      expect(comp.controlCode).toMatch(/^[A-Z0-9.-]+$/);
    }

    // 3. Validar fidelidad de los fragmentos de código y prueba de verificación
    expect(playbook.codeSnippets.length).toBe(1);
    expect(playbook.codeSnippets[0].code).toContain('add_header Strict-Transport-Security');
    expect(playbook.verificationTest.command).toContain('curl');
    expect(playbook.verificationTest.expectedResult).toContain('Strict-Transport-Security');

    // 4. Validar que los snippets de remediación son 100% seguros
    const { blockedCommands } = guardrailService.sanitizeRemediationCommands([
      playbook.codeSnippets[0].code,
      playbook.verificationTest.command,
    ]);
    expect(blockedCommands).toHaveLength(0);
  });

  it('neutralizes dangerous commands injected inside retrieved remediation advice', async () => {
    prismaMock.finding.findFirst.mockResolvedValueOnce({
      id: 'f-insecure',
      ruleId: 'HDR-CSP-MISSING',
      title: 'Vulnerabilidad con código inseguro',
      category: 'HTTP_HEADERS',
      severity: 'HIGH',
      location: 'https://test.empresa.com',
      recommendation: 'Fix CSP',
      assetId: 'a-2',
      asset: { id: 'a-2', value: 'test.empresa.com', type: 'WEB_APPLICATION' },
    });

    // Mock an adversarial snippet that contains dangerous destructive commands
    prismaMock.$queryRawUnsafe
      .mockResolvedValueOnce([
        {
          id: 'iac-danger',
          category: 'REMEDIATION_IAC',
          sourceId: 'IAC-BAD',
          title: 'Remediación Insegura',
          content: '```bash\nchmod -R 777 /var/www && rm -rf /etc/nginx/sites-available\n```',
          metadata: { format: 'bash' },
          similarity: 0.9,
        },
      ])
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce([]);

    const playbook = await ragService.generateRemediationAdvice('f-insecure', 'org-1');

    // Output guardrail must have flagged and blocked the destructive commands
    expect(playbook.codeSnippets[0].code).toContain('[GUARDRAIL BLOCK]');
    expect(playbook.codeSnippets[0].code).toContain('chmod -R 777');
    expect(playbook.codeSnippets[0].code).toContain('rm -rf');
  });
});
