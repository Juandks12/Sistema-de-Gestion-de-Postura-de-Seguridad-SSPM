export type TriageVerdict = 'PROBABLE_FALSE_POSITIVE' | 'NEEDS_VERIFICATION' | 'CONFIRMED_TRUE_POSITIVE';

export type TriageConfidence = 'HIGH' | 'MEDIUM' | 'LOW';

export type TriageRecommendedAction = 'MARK_FALSE_POSITIVE' | 'ACCEPT_RISK' | 'REMEDIATE' | 'RETEST';

export interface TriageContextFactor {
  factor: string;
  impact: 'INCREASES_FP_PROBABILITY' | 'DECREASES_FP_PROBABILITY' | 'NEUTRAL';
  detail: string;
}

export interface FindingTriageAnalysis {
  findingId: string;
  verdict: TriageVerdict;
  confidence: TriageConfidence;
  confidenceScore: number; // 0 a 100
  summary: string;
  reasoning: string[];
  contextFactors: TriageContextFactor[];
  recommendedAction: TriageRecommendedAction;
  suggestedNote: string;
  evaluatedAt: string;
  provider: 'ai' | 'heuristic-expert';
}
