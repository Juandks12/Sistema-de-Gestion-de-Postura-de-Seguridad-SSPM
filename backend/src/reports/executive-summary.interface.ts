export interface BusinessImpact {
  area: 'Operativa' | 'Financiera' | 'Regulatoria/Legal' | 'Reputacional';
  severity: 'CRÍTICO' | 'ALTO' | 'MEDIO' | 'BAJO';
  description: string;
}

export interface StrategicPriority {
  order: number;
  title: string;
  action: string;
  businessJustification: string;
  affectedTarget: string;
}

export interface ExecutiveBusinessSummary {
  headline: string;
  riskLevel: 'CRÍTICO' | 'ALTO' | 'MODERADO' | 'BAJO';
  scoreOverview: {
    score: number | null;
    grade: string | null;
    trendLabel: string;
  };
  executiveOverview: string;
  businessImpacts: BusinessImpact[];
  topPriorities: StrategicPriority[];
  technicalDebtSummary?: string;
  generatedAt: string;
  provider: 'ai' | 'heuristic-expert';
}
