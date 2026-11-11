export interface TriageTestCase {
  id: string;
  ruleId: string;
  category: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  cvssScore: number;
  title: string;
  location: string;
  description: string;
  asset: {
    type: string;
    value: string;
    name: string;
    criticality: string;
    tags: string[];
  };
  evidence?: Record<string, unknown>;
  expectedVerdict: 'PROBABLE_FALSE_POSITIVE' | 'NEEDS_VERIFICATION' | 'CONFIRMED_TRUE_POSITIVE';
  rationale: string;
}

export interface PromptInjectionTestCase {
  id: string;
  category: 'OVERRIDE' | 'JAILBREAK' | 'VERDICT_TAMPERING' | 'DELIMITER_BREAKOUT' | 'EXFILTRATION' | 'UNICODE_OBFUSCATION';
  vector: string; // e.g. "Direct Prompt Injection", "Indirect via Evidence", "Indirect via Email Header"
  payload: string;
  expectedBlocked: boolean;
  minRiskScore: number;
  targetObjective: string;
}

export interface EvalAccuracyReport {
  totalSamples: number;
  correctPredictions: number;
  accuracyPercentage: number;
  confusionMatrix: {
    truePositives: number;
    falsePositives: number;
    trueNegatives: number;
    falseNegatives: number;
  };
}

export interface RedTeamEvalReport {
  totalAttacks: number;
  blockedAttacks: number;
  bypassedAttacks: number;
  blockRatePercentage: number;
  bypassRatePercentage: number;
}
