import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { ReportType } from '@prisma/client';
import { AuthUser } from '../common/interfaces/auth-user.interface';
import { ExecutiveBusinessSummary } from './executive-summary.interface';
import { generateHeuristicSummary as synthesizeHeuristic } from './heuristic-synthesis';
import { ReportData, prioritizedFindings } from './report-data';
import { ReportsService } from './reports.service';

const CACHE_TTL_MS = 60 * 60 * 1000; // 1 hora
const LLM_TIMEOUT_MS = 8000; // 8 segundos

@Injectable()
export class ExecutiveSummaryService {
  private readonly logger = new Logger(ExecutiveSummaryService.name);
  private readonly cache = new Map<string, { summary: ExecutiveBusinessSummary; expiresAt: number }>();

  constructor(
    private readonly reports: ReportsService,
    private readonly config: ConfigService,
  ) {}

  /**
   * Obtiene o genera el Resumen Ejecutivo en lenguaje de negocio.
   * Utiliza proveedor de IA si está configurado (con fallback a motor heurístico experto).
   */
  async getSummary(actor: AuthUser, assetId?: string, forceRefresh = false): Promise<ExecutiveBusinessSummary> {
    const cacheKey = `${actor.organizationId}:${assetId ?? 'all'}`;
    const cached = this.cache.get(cacheKey);

    if (!forceRefresh && cached && cached.expiresAt > Date.now()) {
      return cached.summary;
    }

    const reportData = await this.reports.gather(actor, ReportType.EXECUTIVE, assetId);
    let summary: ExecutiveBusinessSummary;

    const apiKey = this.config.get<string>('AI_API_KEY');
    if (apiKey) {
      try {
        summary = await this.generateWithAi(reportData, apiKey);
      } catch (err) {
        this.logger.warn(`Fallo al generar resumen con IA (${(err as Error).message}). Usando motor heurístico experto.`);
        summary = this.generateHeuristicSummary(reportData);
      }
    } else {
      summary = this.generateHeuristicSummary(reportData);
    }

    this.cache.set(cacheKey, { summary, expiresAt: Date.now() + CACHE_TTL_MS });
    return summary;
  }

  /**
   * Motor heurístico experto: delega al módulo de síntesis para generar el análisis sin LLM.
   */
  generateHeuristicSummary(data: ReportData): ExecutiveBusinessSummary {
    return synthesizeHeuristic(data);
  }

  /**
   * Generación con LLM externo si se proporciona API key.
   */
  private async generateWithAi(data: ReportData, apiKey: string): Promise<ExecutiveBusinessSummary> {
    const apiUrl = this.config.get<string>('AI_API_URL') ?? 'https://api.openai.com/v1';
    const model = this.config.get<string>('AI_MODEL') ?? 'gpt-4o-mini';

    const findings = prioritizedFindings(data).slice(0, 10).map((f) => ({
      title: f.title,
      severity: f.severity,
      cvss: f.cvssScore,
      rule: f.ruleId,
      asset: f.asset,
    }));

    const systemPrompt =
      'Eres un Director de Seguridad de la Información (CISO) y consultor senior de ciberseguridad. ' +
      'Tu tarea es redactar un Resumen Ejecutivo de Postura de Seguridad para la alta gerencia (CEO, CFO, Junta Directiva). ' +
      'El lenguaje debe ser claro, profesional, persuasivo y enfocado en IMPACTO EN EL NEGOCIO (financiero, operativo, reputacional, legal), ' +
      'evitando jerga técnica innecesaria. Debes responder EXCLUSIVAMENTE un objeto JSON válido con la estructura solicitada.';

    const userPrompt = JSON.stringify({
      organizacion: data.organizationName,
      alcance: data.scope,
      scoreActual: data.score.score,
      grado: data.score.grade,
      scoreSemanaPasada: data.score.weekAgoScore,
      conteoPorSeveridad: data.score.counts,
      topHallazgos: findings,
      totalActivos: data.assets.length,
      puertosAbiertos: data.assets.flatMap((a) => a.openPorts.map((p) => `${p.port}/${p.serviceName ?? 'unknown'}`)).slice(0, 10),
    });

    const body = {
      model,
      messages: [
        { role: 'system', content: systemPrompt },
        {
          role: 'user',
          content:
            `Genera el resumen ejecutivo para los siguientes datos de postura de seguridad. ` +
            `Responde únicamente con este JSON:\n` +
            `{\n` +
            `  "headline": "diagnóstico en una frase clara",\n` +
            `  "riskLevel": "CRÍTICO | ALTO | MODERADO | BAJO",\n` +
            `  "scoreOverview": { "score": number, "grade": string, "trendLabel": string },\n` +
            `  "executiveOverview": "párrafo de 3-4 oraciones en lenguaje de negocio",\n` +
            `  "businessImpacts": [\n` +
            `    { "area": "Operativa", "severity": "CRÍTICO | ALTO | MEDIO | BAJO", "description": "impacto" },\n` +
            `    { "area": "Financiera", "severity": "...", "description": "..." },\n` +
            `    { "area": "Regulatoria/Legal", "severity": "...", "description": "..." },\n` +
            `    { "area": "Reputacional", "severity": "...", "description": "..." }\n` +
            `  ],\n` +
            `  "topPriorities": [\n` +
            `    { "order": 1, "title": "título", "action": "acción recomendada", "businessJustification": "por qué priorizarlo", "affectedTarget": "alcance" }\n` +
            `  ],\n` +
            `  "technicalDebtSummary": "resumen de deuda técnica"\n` +
            `}\n\nDatos:\n${userPrompt}`,
        },
      ],
      temperature: 0.3,
    };

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), LLM_TIMEOUT_MS);

    try {
      const response = await fetch(`${apiUrl}/chat/completions`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${apiKey}`,
        },
        body: JSON.stringify(body),
        signal: controller.signal,
      });

      if (!response.ok) {
        throw new Error(`LLM API respondió ${response.status}: ${await response.text()}`);
      }

      const raw = (await response.json()) as { choices?: Array<{ message?: { content?: string } }> };
      const content = raw.choices?.[0]?.message?.content;
      if (!content) throw new Error('Respuesta vacía del proveedor LLM');

      const cleanJson = content.replace(/^```json\s*/, '').replace(/```\s*$/, '').trim();
      const parsed = JSON.parse(cleanJson) as ExecutiveBusinessSummary;

      return {
        ...parsed,
        generatedAt: new Date().toISOString(),
        provider: 'ai',
      };
    } finally {
      clearTimeout(timeout);
    }
  }
}
