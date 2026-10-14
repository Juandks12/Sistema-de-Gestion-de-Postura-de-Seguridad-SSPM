import { Injectable, Logger, NotFoundException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../prisma/prisma.service';
import { evaluateHeuristicTriage, TriageFindingInput } from './heuristic-triage';
import { FindingTriageAnalysis } from './triage.interface';

const CACHE_TTL_MS = 60 * 60 * 1000; // 1 hora
const LLM_TIMEOUT_MS = 8000; // 8 segundos

@Injectable()
export class FindingTriageService {
  private readonly logger = new Logger(FindingTriageService.name);
  private readonly cache = new Map<string, { analysis: FindingTriageAnalysis; expiresAt: number }>();

  constructor(
    private readonly prisma: PrismaService,
    private readonly config: ConfigService,
  ) {}

  /**
   * Genera o recupera el análisis de triage asistido para un hallazgo específico.
   * Utiliza LLM si AI_API_KEY está configurada, con fallback automático al motor heurístico experto.
   */
  async analyze(organizationId: string, findingId: string, forceRefresh = false): Promise<FindingTriageAnalysis> {
    const cacheKey = `${organizationId}:${findingId}`;
    const cached = this.cache.get(cacheKey);

    if (!forceRefresh && cached && cached.expiresAt > Date.now()) {
      return cached.analysis;
    }

    const finding = await this.prisma.finding.findFirst({
      where: { id: findingId, organizationId },
      select: {
        id: true,
        ruleId: true,
        category: true,
        severity: true,
        cvssScore: true,
        title: true,
        description: true,
        location: true,
        evidence: true,
        asset: {
          select: {
            id: true,
            type: true,
            value: true,
            name: true,
            criticality: true,
            tags: true,
          },
        },
      },
    });

    if (!finding) {
      throw new NotFoundException('Hallazgo no encontrado');
    }

    const input: TriageFindingInput = {
      id: finding.id,
      ruleId: finding.ruleId,
      category: finding.category,
      severity: finding.severity,
      cvssScore: finding.cvssScore !== null ? Number(finding.cvssScore) : 0,
      title: finding.title,
      description: finding.description,
      location: finding.location,
      evidence: (finding.evidence as Record<string, unknown>) ?? {},
      asset: {
        id: finding.asset.id,
        type: finding.asset.type,
        value: finding.asset.value,
        name: finding.asset.name,
        criticality: finding.asset.criticality,
        tags: finding.asset.tags,
      },
    };

    let analysis: FindingTriageAnalysis;
    const apiKey = this.config.get<string>('AI_API_KEY');

    if (apiKey) {
      try {
        analysis = await this.generateWithAi(input, apiKey);
      } catch (err) {
        this.logger.warn(`Fallo al generar triage con IA (${(err as Error).message}). Usando motor heurístico experto.`);
        analysis = evaluateHeuristicTriage(input);
      }
    } else {
      analysis = evaluateHeuristicTriage(input);
    }

    this.cache.set(cacheKey, { analysis, expiresAt: Date.now() + CACHE_TTL_MS });
    return analysis;
  }

  /**
   * Llamada al proveedor LLM externo.
   */
  private async generateWithAi(input: TriageFindingInput, apiKey: string): Promise<FindingTriageAnalysis> {
    const apiUrl = this.config.get<string>('AI_API_URL') ?? 'https://api.openai.com/v1';
    const model = this.config.get<string>('AI_MODEL') ?? 'gpt-4o-mini';

    const systemPrompt =
      'Eres un analista senior de seguridad de aplicaciones (AppSec) y triage de vulnerabilidades. ' +
      'Tu labor es evaluar objetivamente si un hallazgo técnico de seguridad es un PROBABLE FALSO POSITIVO dado el contexto del activo ' +
      '(por ejemplo, APIs sin renderizado HTML con falta de CSP, puertos legítimos de DNS en servidores de nombres, entornos de pruebas, etc.) ' +
      'o si es un RIESGO CONFIRMADO que debe remediarse. ' +
      'Debes responder EXCLUSIVAMENTE un objeto JSON válido con la siguiente estructura: ' +
      '{\n' +
      '  "verdict": "PROBABLE_FALSE_POSITIVE" | "NEEDS_VERIFICATION" | "CONFIRMED_TRUE_POSITIVE",\n' +
      '  "confidence": "HIGH" | "MEDIUM" | "LOW",\n' +
      '  "confidenceScore": number (0 a 100),\n' +
      '  "summary": string (1-2 oraciones directas),\n' +
      '  "reasoning": string[] (argumentos técnicos sustentados en el contexto del activo),\n' +
      '  "contextFactors": [{ "factor": string, "impact": "INCREASES_FP_PROBABILITY" | "DECREASES_FP_PROBABILITY" | "NEUTRAL", "detail": string }],\n' +
      '  "recommendedAction": "MARK_FALSE_POSITIVE" | "ACCEPT_RISK" | "REMEDIATE" | "RETEST",\n' +
      '  "suggestedNote": string (nota concisa para registrar en la plataforma)\n' +
      '}';

    const userContent = JSON.stringify({
      finding: {
        ruleId: input.ruleId,
        category: input.category,
        severity: input.severity,
        cvss: input.cvssScore,
        title: input.title,
        location: input.location,
        evidence: input.evidence,
      },
      asset: {
        type: input.asset.type,
        value: input.asset.value,
        name: input.asset.name,
        criticality: input.asset.criticality,
        tags: input.asset.tags,
      },
    });

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), LLM_TIMEOUT_MS);

    try {
      const response = await fetch(`${apiUrl.replace(/\/+$/, '')}/chat/completions`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${apiKey}`,
        },
        body: JSON.stringify({
          model,
          temperature: 0.1,
          response_format: { type: 'json_object' },
          messages: [
            { role: 'system', content: systemPrompt },
            { role: 'user', content: userContent },
          ],
        }),
        signal: controller.signal,
      });

      if (!response.ok) {
        const text = await response.text();
        throw new Error(`LLM API responded with ${response.status}: ${text.slice(0, 150)}`);
      }

      const body = (await response.json()) as { choices?: Array<{ message?: { content?: string } }> };
      const rawContent = body.choices?.[0]?.message?.content;
      if (!rawContent) {
        throw new Error('LLM response returned empty content');
      }

      const parsed = JSON.parse(rawContent) as Partial<FindingTriageAnalysis>;
      if (!parsed.verdict || !parsed.confidence || !parsed.summary || !Array.isArray(parsed.reasoning)) {
        throw new Error('LLM response missing required triage fields');
      }

      return {
        findingId: input.id,
        verdict: parsed.verdict,
        confidence: parsed.confidence,
        confidenceScore: typeof parsed.confidenceScore === 'number' ? parsed.confidenceScore : 75,
        summary: parsed.summary,
        reasoning: parsed.reasoning,
        contextFactors: Array.isArray(parsed.contextFactors) ? parsed.contextFactors : [],
        recommendedAction: parsed.recommendedAction ?? 'RETEST',
        suggestedNote: parsed.suggestedNote ?? '',
        evaluatedAt: new Date().toISOString(),
        provider: 'ai',
      };
    } finally {
      clearTimeout(timeout);
    }
  }
}
