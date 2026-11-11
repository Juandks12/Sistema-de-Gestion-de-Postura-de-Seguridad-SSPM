import { PrismaService } from '../../prisma/prisma.service';
import { LlmObservabilityService } from './llm-observability.service';

describe('LlmObservabilityService', () => {
  let service: LlmObservabilityService;
  let prismaMock: {
    llmExecutionLog: {
      create: jest.Mock;
      findMany: jest.Mock;
    };
  };

  beforeEach(() => {
    prismaMock = {
      llmExecutionLog: {
        create: jest.fn(),
        findMany: jest.fn(),
      },
    };

    service = new LlmObservabilityService(prismaMock as unknown as PrismaService);
  });

  describe('calculateCostUsd()', () => {
    it('calculates cost correctly for gpt-4o-mini', () => {
      // Prompt: $0.15 / 1M = 0.00015 for 1,000 tokens
      // Completion: $0.60 / 1M = 0.0006 for 1,000 tokens
      // Total: 0.00075 USD
      const cost = service.calculateCostUsd('gpt-4o-mini', 1000, 1000);
      expect(cost).toBe(0.00075);
    });

    it('calculates cost correctly for gemini-1.5-flash', () => {
      // Prompt: $0.075 / 1M = 0.000075 for 1,000 tokens
      // Completion: $0.30 / 1M = 0.0003 for 1,000 tokens
      // Total: 0.000375 USD
      const cost = service.calculateCostUsd('gemini-1.5-flash', 1000, 1000);
      expect(cost).toBe(0.000375);
    });

    it('calculates cost correctly for text-embedding-3-small', () => {
      // Prompt: $0.02 / 1M = 0.00002 for 1,000 tokens
      // Completion: 0
      const cost = service.calculateCostUsd('text-embedding-3-small', 1000, 0);
      expect(cost).toBe(0.00002);
    });
  });

  describe('recordExecution()', () => {
    it('persists structured execution telemetry with decimal cost', async () => {
      prismaMock.llmExecutionLog.create.mockResolvedValueOnce({ id: 'log-1' });

      await service.recordExecution({
        organizationId: 'org-1',
        agentOrService: 'Finding Triage AI',
        model: 'gpt-4o-mini',
        promptTokens: 500,
        completionTokens: 200,
        latencyMs: 320,
        status: 'SUCCESS',
      });

      expect(prismaMock.llmExecutionLog.create).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            organizationId: 'org-1',
            agentOrService: 'Finding Triage AI',
            model: 'gpt-4o-mini',
            promptTokens: 500,
            completionTokens: 200,
            totalTokens: 700,
            latencyMs: 320,
            status: 'SUCCESS',
            promptInjectionDetected: false,
          }),
        }),
      );
    });

    it('handles database errors gracefully without throwing', async () => {
      prismaMock.llmExecutionLog.create.mockRejectedValueOnce(new Error('DB Connection down'));

      const result = await service.recordExecution({
        organizationId: 'org-1',
        agentOrService: 'Finding Triage AI',
        model: 'gpt-4o-mini',
        promptTokens: 100,
        completionTokens: 50,
        latencyMs: 100,
      });

      expect(result).toBeNull();
    });
  });

  describe('getStats()', () => {
    it('aggregates tokens, costs, average latency, and prompt injection metrics', async () => {
      const mockLogs = [
        {
          id: 'l1',
          agentOrService: 'Finding Triage AI',
          model: 'gpt-4o-mini',
          totalTokens: 1000,
          estimatedCostUsd: 0.00075,
          latencyMs: 300,
          status: 'SUCCESS',
          promptInjectionDetected: false,
        },
        {
          id: 'l2',
          agentOrService: 'Threat Lab Email Guard',
          model: 'gemini-1.5-flash',
          totalTokens: 500,
          estimatedCostUsd: 0.00018,
          latencyMs: 200,
          status: 'BLOCKED_INJECTION',
          promptInjectionDetected: true,
        },
        {
          id: 'l3',
          agentOrService: 'Finding Triage AI',
          model: 'gpt-4o-mini',
          totalTokens: 0,
          estimatedCostUsd: 0,
          latencyMs: 0,
          status: 'FALLBACK_HEURISTIC',
          promptInjectionDetected: false,
        },
      ];

      prismaMock.llmExecutionLog.findMany.mockResolvedValueOnce(mockLogs);

      const stats = await service.getStats('org-1', 7);

      expect(stats.totalCalls).toBe(3);
      expect(stats.totalTokens).toBe(1500);
      expect(stats.totalCostUsd).toBeCloseTo(0.00093, 4);
      expect(stats.promptInjectionsBlocked).toBe(1);
      expect(stats.fallbackRatePercent).toBeCloseTo(33.33, 1);
      expect(stats.averageLatencyMs).toBe(167);
      expect(stats.byAgent['Finding Triage AI'].calls).toBe(2);
      expect(stats.byAgent['Threat Lab Email Guard'].calls).toBe(1);
    });
  });
});
