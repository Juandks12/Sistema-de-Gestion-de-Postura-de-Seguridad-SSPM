import { Injectable, Logger, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';
import { EmbeddingService } from '../embeddings/embedding.service';
import { KnowledgeCategoryEnum, RagSearchDto } from './dto/rag-search.dto';

export interface RagDocumentResult {
  id: string;
  category: string;
  sourceId: string | null;
  title: string;
  content: string;
  metadata: Record<string, unknown> | null;
  similarity: number;
}

export interface GroundedRemediationPlaybook {
  findingId: string;
  ruleId: string;
  title: string;
  severity: string;
  asset: {
    id: string;
    target: string;
    type: string;
  };
  rootCauseAnalysis: string;
  complianceImpact: Array<{
    framework: string;
    controlCode: string;
    title: string;
  }>;
  stepByStepRemediation: string[];
  codeSnippets: Array<{
    language: string;
    description: string;
    code: string;
  }>;
  verificationTest: {
    command: string;
    expectedResult: string;
    description: string;
  };
  groundedCitations: Array<{
    sourceId: string;
    title: string;
    category: string;
    similarityScore: number;
  }>;
  generatedAt: string;
}

@Injectable()
export class RagRetrievalService {
  private readonly logger = new Logger(RagRetrievalService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly embeddingService: EmbeddingService,
  ) {}

  /**
   * Búsqueda semántica de conocimiento con similitud coseno en pgvector.
   */
  async searchSemantic(dto: RagSearchDto): Promise<RagDocumentResult[]> {
    const { query, category, limit = 5, minSimilarity = 0.05 } = dto;
    const embedding = await this.embeddingService.generateEmbedding(query);
    const vectorString = `[${embedding.join(',')}]`;

    const rawRows = (await this.prisma.$queryRawUnsafe(
      `SELECT 
        id, 
        category::text AS category, 
        source_id AS "sourceId", 
        title, 
        content, 
        metadata, 
        ROUND((1 - (embedding <=> $1::vector))::numeric, 4)::float AS similarity
      FROM knowledge_embeddings
      WHERE ($2::text IS NULL OR category::text = $2::text)
        AND embedding IS NOT NULL
        AND (1 - (embedding <=> $1::vector)) >= $3
      ORDER BY embedding <=> $1::vector ASC
      LIMIT $4;`,
      vectorString,
      category || null,
      minSimilarity,
      limit,
    )) as RagDocumentResult[];

    return rawRows.map((row) => ({
      ...row,
      similarity: Number(row.similarity),
    }));
  }

  /**
   * Genera un playbook de remediación grounded y contextualizado para un hallazgo específico.
   */
  async generateRemediationAdvice(
    findingId: string,
    organizationId: string,
    customContext?: string,
  ): Promise<GroundedRemediationPlaybook> {
    const finding = await this.prisma.finding.findFirst({
      where: { id: findingId, organizationId },
      include: { asset: true },
    });

    if (!finding) {
      throw new NotFoundException(`Hallazgo no encontrado o sin permisos en la organización: ${findingId}`);
    }

    // 1. Consulta RAG semántica cruzando ruleId, título, descripción y contexto
    const query = `${finding.ruleId} ${finding.title} ${finding.category} ${finding.location} ${finding.recommendation} ${customContext || ''}`;

    const [iacSnippets, guides, complianceDocs, kevEntries] = await Promise.all([
      this.searchSemantic({ query, category: KnowledgeCategoryEnum.REMEDIATION_IAC, limit: 3, minSimilarity: 0.05 }),
      this.searchSemantic({ query, category: KnowledgeCategoryEnum.HARDENING_GUIDE, limit: 3, minSimilarity: 0.05 }),
      this.searchSemantic({ query, category: KnowledgeCategoryEnum.GRC_CONTROL, limit: 4, minSimilarity: 0.05 }),
      this.searchSemantic({ query, category: KnowledgeCategoryEnum.CVE, limit: 2, minSimilarity: 0.05 }),
    ]);

    const allRetrieved = [...iacSnippets, ...guides, ...complianceDocs, ...kevEntries].sort(
      (a, b) => b.similarity - a.similarity,
    );

    // 2. Extraer controles GRC impactados
    const complianceImpact = complianceDocs.map((doc) => {
      const meta = (doc.metadata || {}) as Record<string, string>;
      return {
        framework: meta.framework || 'GRC',
        controlCode: meta.code || doc.sourceId || 'CONTROL',
        title: doc.title,
      };
    });

    // 3. Extraer snippets de código
    const codeSnippets: Array<{ language: string; description: string; code: string }> = [];
    for (const iac of iacSnippets) {
      const meta = (iac.metadata || {}) as Record<string, string>;
      // Extraer bloque de código si está formateado con markdown
      const match = iac.content.match(/```([a-z0-9_-]+)\n([\s\S]*?)```/i);
      codeSnippets.push({
        language: meta.format || match?.[1] || 'bash',
        description: iac.title,
        code: match ? match[2].trim() : iac.content,
      });
    }

    // Snippet por defecto si no hubo match en base vectorial
    if (codeSnippets.length === 0 && guides.length > 0) {
      codeSnippets.push({
        language: 'nginx',
        description: `Directivas de mitigación recomendadas para ${finding.title}`,
        code: guides[0].content,
      });
    }

    // 4. Formular pasos de remediación
    const stepByStepRemediation: string[] = [
      `Validar la ubicación afectada: '${finding.location}' en el activo '${finding.asset?.value || 'N/A'}'.`,
      `Revisar la configuración actual del servidor web, proxy inverso o proveedor de nube.`,
      `Aplicar el fragmento de configuración o script de remediación (ver Code Snippets) en el entorno de Staging.`,
      `Ejecutar la prueba de verificación técnica para asegurar que el control responde correctamente sin interrumpir el servicio.`,
      `Promover a Producción y volver a lanzar el escaneo SSPM para verificar la resolución automática del hallazgo.`,
    ];

    // 5. Prueba de verificación técnica
    const verificationTest = this.buildVerificationTest(finding.ruleId, finding.location, finding.asset?.value);

    // 6. Análisis de causa raíz
    const primaryGuide = guides[0]?.content || finding.description;
    const rootCauseAnalysis = `El hallazgo '${finding.title}' fue detectado con severidad ${finding.severity} debido a una brecha de configuración en '${finding.location}'.\n\nContexto Grounded RAG:\n${primaryGuide.slice(0, 400)}...`;

    return {
      findingId: finding.id,
      ruleId: finding.ruleId,
      title: finding.title,
      severity: finding.severity,
      asset: {
        id: finding.assetId,
        target: finding.asset?.value || 'N/A',
        type: finding.asset?.type || 'UNKNOWN',
      },
      rootCauseAnalysis,
      complianceImpact,
      stepByStepRemediation,
      codeSnippets,
      verificationTest,
      groundedCitations: allRetrieved.slice(0, 6).map((r) => ({
        sourceId: r.sourceId || r.id,
        title: r.title,
        category: r.category,
        similarityScore: r.similarity,
      })),
      generatedAt: new Date().toISOString(),
    };
  }

  private buildVerificationTest(
    ruleId: string,
    location: string,
    assetTarget?: string,
  ): { command: string; expectedResult: string; description: string } {
    const targetUrl = location.startsWith('http') ? location : `https://${assetTarget || 'localhost'}`;

    if (ruleId.includes('HSTS')) {
      return {
        command: `curl -s -I "${targetUrl}" | grep -i "Strict-Transport-Security"`,
        expectedResult: 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
        description: 'Verifica la presencia y directivas completas de la cabecera HSTS en la respuesta HTTP.',
      };
    }

    if (ruleId.includes('CSP')) {
      return {
        command: `curl -s -I "${targetUrl}" | grep -i "Content-Security-Policy"`,
        expectedResult: 'Content-Security-Policy: default-src \'self\' ...',
        description: 'Verifica que la cabecera Content-Security-Policy esté configurada y no permita inyecciones externas.',
      };
    }

    if (ruleId.includes('FRAME') || ruleId.includes('CLICKJACKING')) {
      return {
        command: `curl -s -I "${targetUrl}" | grep -Ei "X-Frame-Options|frame-ancestors"`,
        expectedResult: 'X-Frame-Options: DENY (o SAMEORIGIN)',
        description: 'Verifica la protección contra incrustación no autorizada en frames.',
      };
    }

    if (ruleId.includes('TLS') || ruleId.includes('SSL')) {
      return {
        command: `openssl s_client -connect ${assetTarget || 'localhost'}:443 -tls1_2 < /dev/null`,
        expectedResult: 'Cipher is ECDHE-... Protocol: TLSv1.2 (o TLSv1.3)',
        description: 'Verifica que el handshake TLS negocie una versión segura y un cifrado moderno.',
      };
    }

    if (ruleId.includes('PORT') || location.startsWith('tcp/')) {
      const port = location.split('/')[1] || '22';
      return {
        command: `nmap -sV -p ${port} ${assetTarget || 'localhost'}`,
        expectedResult: `Host is up. ${port}/tcp filtered (o cerrado/restringido)`,
        description: 'Comprueba que el puerto ya no se encuentre expuesto abiertamente a Internet.',
      };
    }

    return {
      command: `curl -s -I "${targetUrl}"`,
      expectedResult: 'HTTP/2 200 (con cabeceras de seguridad validadas)',
      description: 'Valida la respuesta HTTP y confirma que no se exponen vectores de ataque.',
    };
  }
}
