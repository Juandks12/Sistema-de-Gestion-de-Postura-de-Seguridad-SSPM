import { Injectable, Logger } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { PrismaService } from '../../prisma/prisma.service';

export interface RecordLlmExecutionInput {
  organizationId: string;
  agentOrService: string;
  model: string;
  promptTokens: number;
  completionTokens: number;
  latencyMs: number;
  ttftMs?: number;
  status?: 'SUCCESS' | 'FALLBACK_HEURISTIC' | 'BLOCKED_INJECTION' | 'ERROR';
  promptInjectionDetected?: boolean;
  promptInjectionScore?: number;
  detectedPatterns?: string[];
  fallbackReason?: string;
}

export interface LlmObservabilityStats {
  totalCalls: number;
  totalTokens: number;
  totalCostUsd: number;
  averageLatencyMs: number;
  fallbackRatePercent: number;
  promptInjectionsBlocked: number;
  byAgent: Record<string, { calls: number; costUsd: number; tokens: number }>;
  byModel: Record<string, { calls: number; costUsd: number }>;
}

const MODEL_COSTS_PER_MILLION: Record<string, { promptUsd: number; completionUsd: number }> = {
  'gemini-1.5-flash': { promptUsd: 0.075, completionUsd: 0.3 },
  'gemini-1.5-pro': { promptUsd: 3.5, completionUsd: 10.5 },
  'gpt-4o-mini': { promptUsd: 0.15, completionUsd: 0.6 },
  'gpt-4o': { promptUsd: 2.5, completionUsd: 10.0 },
  'text-embedding-3-small': { promptUsd: 0.02, completionUsd: 0.0 },
  'text-embedding-004': { promptUsd: 0.0, completionUsd: 0.0 },
};

@Injectable()
export class LlmObservabilityService {
  private readonly logger = new Logger(LlmObservabilityService.name);

  constructor(private readonly prisma: PrismaService) {}

  /**
   * Calcula el costo estimado en dólares a partir del modelo y tokens consumidos.
   */
  calculateCostUsd(model: string, promptTokens: number, completionTokens: number): number {
    const key = Object.keys(MODEL_COSTS_PER_MILLION).find((k) =>
      model.toLowerCase().includes(k.toLowerCase()),
    );
    const pricing = key ? MODEL_COSTS_PER_MILLION[key] : { promptUsd: 0.2, completionUsd: 0.8 };

    const promptCost = (promptTokens / 1_000_000) * pricing.promptUsd;
    const completionCost = (completionTokens / 1_000_000) * pricing.completionUsd;

    return Number((promptCost + completionCost).toFixed(6));
  }

  /**
   * Registra una ejecución con telemetría estructurada.
   */
  async recordExecution(input: RecordLlmExecutionInput) {
    const totalTokens = input.promptTokens + input.completionTokens;
    const costUsd = this.calculateCostUsd(input.model, input.promptTokens, input.completionTokens);

    try {
      return await this.prisma.llmExecutionLog.create({
        data: {
          organizationId: input.organizationId,
          agentOrService: input.agentOrService,
          model: input.model,
          promptTokens: input.promptTokens,
          completionTokens: input.completionTokens,
          totalTokens,
          estimatedCostUsd: new Prisma.Decimal(costUsd),
          latencyMs: input.latencyMs,
          ttftMs: input.ttftMs,
          status: input.status || 'SUCCESS',
          promptInjectionDetected: input.promptInjectionDetected ?? false,
          promptInjectionScore: input.promptInjectionScore,
          detectedPatterns: input.detectedPatterns || [],
          fallbackReason: input.fallbackReason,
        },
      });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      this.logger.warn(`No se pudo persistir log de observabilidad de LLM: ${msg}`);
      return null;
    }
  }

  /**
   * Obtiene métricas agregadas de consumo de IA por organización.
   */
  async getStats(organizationId: string, days = 30): Promise<LlmObservabilityStats> {
    const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000);

    const logs = await this.prisma.llmExecutionLog.findMany({
      where: {
        organizationId,
        createdAt: { gte: since },
      },
      orderBy: { createdAt: 'desc' },
    });

    let totalTokens = 0;
    let totalCostUsd = 0;
    let totalLatency = 0;
    let fallbackCalls = 0;
    let promptInjectionsBlocked = 0;

    const byAgent: Record<string, { calls: number; costUsd: number; tokens: number }> = {};
    const byModel: Record<string, { calls: number; costUsd: number }> = {};

    for (const log of logs) {
      totalTokens += log.totalTokens;
      const cost = Number(log.estimatedCostUsd);
      totalCostUsd += cost;
      totalLatency += log.latencyMs;

      if (log.status === 'FALLBACK_HEURISTIC') fallbackCalls++;
      if (log.promptInjectionDetected) promptInjectionsBlocked++;

      // Agregado por agente
      if (!byAgent[log.agentOrService]) {
        byAgent[log.agentOrService] = { calls: 0, costUsd: 0, tokens: 0 };
      }
      byAgent[log.agentOrService].calls++;
      byAgent[log.agentOrService].costUsd = Number(
        (byAgent[log.agentOrService].costUsd + cost).toFixed(6),
      );
      byAgent[log.agentOrService].tokens += log.totalTokens;

      // Agregado por modelo
      if (!byModel[log.model]) {
        byModel[log.model] = { calls: 0, costUsd: 0 };
      }
      byModel[log.model].calls++;
      byModel[log.model].costUsd = Number((byModel[log.model].costUsd + cost).toFixed(6));
    }

    const totalCalls = logs.length;
    const averageLatencyMs = totalCalls > 0 ? Math.round(totalLatency / totalCalls) : 0;
    const fallbackRatePercent = totalCalls > 0 ? Number(((fallbackCalls / totalCalls) * 100).toFixed(1)) : 0;

    return {
      totalCalls,
      totalTokens,
      totalCostUsd: Number(totalCostUsd.toFixed(4)),
      averageLatencyMs,
      fallbackRatePercent,
      promptInjectionsBlocked,
      byAgent,
      byModel,
    };
  }

  /**
   * Lista los últimos registros de telemetría para depuración y auditoría.
   */
  async getRecentLogs(organizationId: string, limit = 20) {
    return this.prisma.llmExecutionLog.findMany({
      where: { organizationId },
      orderBy: { createdAt: 'desc' },
      take: Math.min(Math.max(limit, 1), 100),
    });
  }
}
