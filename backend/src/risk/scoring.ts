import { AssetCriticality, FindingSeverity } from '@prisma/client';

/**
 * Motor de riesgo y Security Score (RF-07), sección 6.3 del documento.
 *
 * Modelo de puntuación:
 *   Score = 100 - Σ min(Tope_s, Peso_s × FactorCriticidad × N_s)   para cada severidad s
 *   acotado al rango [0, 100].
 *
 * - Solo cuentan los hallazgos en estado OPEN. Los ACCEPTED (riesgo aceptado),
 *   FALSE_POSITIVE y RESOLVED no penalizan.
 * - Los pesos derivan de la severidad CVSS v3.1 de cada regla (6.3.3): un solo
 *   hallazgo crítico deja la postura en 75 (o 62 en activo CRITICAL) y cuatro la llevan a 0.
 * - Cada severidad tiene un tope de penalización (6.3.4) para que muchos
 *   hallazgos menores no oculten uno crítico ni hundan el score por sí solos.
 * - La calificación por letra (6.3.5) traduce el número a un nivel comprensible.
 * - Incorpora la fórmula de riesgo híbrida: Riesgo = CVSS × (1 + EPSS) × FactorCriticidad.
 *
 * Las constantes están aquí, en un único sitio, para poder ajustarlas tras el
 * caso de estudio (sección 13.4) sin tocar el resto del sistema.
 */

export const SCORING_MODEL_VERSION = '1.1';

/** Penalización por cada hallazgo abierto de la severidad (línea base). */
export const SEVERITY_WEIGHTS: Record<FindingSeverity, number> = {
  CRITICAL: 25,
  HIGH: 10,
  MEDIUM: 4,
  LOW: 1,
  INFO: 0,
};

/** Penalización máxima acumulada por severidad. */
export const SEVERITY_CAPS: Record<FindingSeverity, number> = {
  CRITICAL: 100,
  HIGH: 60,
  MEDIUM: 30,
  LOW: 10,
  INFO: 0,
};

/** Multiplicador de impacto según la criticidad del activo para la organización. */
export const CRITICALITY_FACTORS: Record<AssetCriticality, number> = {
  CRITICAL: 1.5,
  HIGH: 1.25,
  MEDIUM: 1.0,
  LOW: 0.75,
};

export const SEVERITY_ORDER: FindingSeverity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

export type Grade = 'A' | 'B' | 'C' | 'D' | 'F';

export interface GradeBand {
  grade: Grade;
  min: number;
  label: string;
  description: string;
}

/** Clasificación por criticidad (6.3.5). */
export const GRADE_BANDS: GradeBand[] = [
  { grade: 'A', min: 90, label: 'Excelente', description: 'Sin exposiciones relevantes. Mantener el monitoreo.' },
  { grade: 'B', min: 75, label: 'Buena', description: 'Exposiciones menores. Corregir en el próximo ciclo de mantenimiento.' },
  { grade: 'C', min: 60, label: 'Aceptable', description: 'Existen riesgos medios o altos que requieren un plan de corrección.' },
  { grade: 'D', min: 40, label: 'Deficiente', description: 'Riesgos altos abiertos. Priorizar la remediación esta semana.' },
  { grade: 'F', min: 0, label: 'Crítica', description: 'Exposiciones críticas activas. Actuar de inmediato.' },
];

export type SeverityCounts = Record<FindingSeverity, number>;

export interface SeverityPenalty {
  severity: FindingSeverity;
  count: number;
  weight: number;
  cap: number;
  /** Penalización aplicada = min(cap, weight × count). */
  penalty: number;
  /** true si la penalización quedó limitada por el tope. */
  capped: boolean;
}

export interface ScoreResult {
  score: number;
  grade: Grade;
  label: string;
  description: string;
  totalPenalty: number;
  penalties: SeverityPenalty[];
  counts: SeverityCounts;
  criticality: AssetCriticality;
  criticalityFactor: number;
  modelVersion: string;
}

export function emptyCounts(): SeverityCounts {
  return { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
}

export function gradeFor(score: number): GradeBand {
  const band = GRADE_BANDS.find((b) => score >= b.min);
  return band ?? GRADE_BANDS[GRADE_BANDS.length - 1];
}

/**
 * Calcula el riesgo compuesto de un hallazgo o CVE mediante la fórmula híbrida:
 * Riesgo = CVSS × (1 + EPSS) × FactorCriticidad
 */
export function computeHybridRisk(
  cvss: number,
  epss: number = 0,
  criticality: AssetCriticality = AssetCriticality.MEDIUM,
): number {
  const boundedCvss = Math.max(0, Math.min(10, cvss));
  const boundedEpss = Math.max(0, Math.min(1, epss));
  const factor = CRITICALITY_FACTORS[criticality] ?? 1.0;
  const rawRisk = boundedCvss * (1 + boundedEpss) * factor;
  return Math.round(rawRisk * 100) / 100;
}

/** Calcula el Security Score a partir del conteo de hallazgos abiertos por severidad y la criticidad del activo. */
export function computeScore(
  counts: Partial<SeverityCounts>,
  criticality: AssetCriticality = AssetCriticality.MEDIUM,
): ScoreResult {
  const full: SeverityCounts = { ...emptyCounts(), ...counts };
  const criticalityFactor = CRITICALITY_FACTORS[criticality] ?? 1.0;

  const penalties: SeverityPenalty[] = SEVERITY_ORDER.map((severity) => {
    const count = Math.max(0, Math.floor(full[severity] ?? 0));
    const baseWeight = SEVERITY_WEIGHTS[severity];
    const weight = Math.round(baseWeight * criticalityFactor * 100) / 100;
    const cap = SEVERITY_CAPS[severity];
    const raw = Math.round(weight * count * 100) / 100;
    return { severity, count, weight, cap, penalty: Math.min(cap, raw), capped: raw > cap };
  });

  const totalPenalty = Math.round(penalties.reduce((acc, p) => acc + p.penalty, 0));
  const score = Math.max(0, Math.min(100, 100 - totalPenalty));
  const band = gradeFor(score);
  return {
    score,
    grade: band.grade,
    label: band.label,
    description: band.description,
    totalPenalty,
    penalties,
    counts: full,
    criticality,
    criticalityFactor,
    modelVersion: SCORING_MODEL_VERSION,
  };
}

/**
 * Score de la organización: media de los scores de sus activos evaluados.
 * Se usa la media (y no la fórmula sobre el total de hallazgos) para que la
 * puntuación no dependa del número de activos registrados; los conteos
 * globales se reportan aparte para no ocultar la gravedad.
 */
export function aggregateScores(assetScores: number[]): number | null {
  if (assetScores.length === 0) return null;
  const sum = assetScores.reduce((acc, s) => acc + s, 0);
  return Math.round(sum / assetScores.length);
}

export function describeModel() {
  return {
    version: SCORING_MODEL_VERSION,
    formula: 'score = clamp(100 - Σ min(cap[s], weight[s] × factor × open[s]), 0, 100)',
    countsOnly: ['OPEN'],
    excluded: ['RESOLVED', 'ACCEPTED', 'FALSE_POSITIVE'],
    weights: SEVERITY_WEIGHTS,
    caps: SEVERITY_CAPS,
    criticalityFactors: CRITICALITY_FACTORS,
    hybridRiskFormula: 'Riesgo = CVSS * (1 + EPSS) * FactorCriticidad',
    organizationScore: 'media redondeada de los scores de los activos con al menos un escaneo completado',
    grades: GRADE_BANDS,
  };
}

export interface ScoreStats {
  mean: number;
  stdDev: number;
}

export function calculateScoreStats(scores: number[]): ScoreStats {
  if (scores.length === 0) return { mean: 0, stdDev: 0 };
  const mean = scores.reduce((sum, s) => sum + s, 0) / scores.length;
  if (scores.length === 1) return { mean: Math.round(mean * 10) / 10, stdDev: 0 };
  const variance = scores.reduce((sum, s) => sum + Math.pow(s - mean, 2), 0) / (scores.length - 1);
  const stdDev = Math.sqrt(variance);
  return {
    mean: Math.round(mean * 10) / 10,
    stdDev: Math.round(stdDev * 10) / 10,
  };
}

export interface ScoreAnomalyEvaluation {
  isAnomaly: boolean;
  drop: number;
  zScore?: number;
  mean?: number;
  stdDev?: number;
  severity?: FindingSeverity;
}

/**
 * Evalúa si una variación en el Security Score representa una anomalía estadística
 * o un descenso atípico relevante.
 * - Caídas < 10 puntos nunca alertan.
 * - En activos con histórico (>= 3 muestras), evalúa Z-Score (z >= 2.0 = anomalía atípica).
 * - Caídas abruptas (>= 15 pts, o >= 12 pts si el score cae a zona crítica < 50) se consideran anomalías directas.
 */
export function evaluateScoreAnomaly(
  currentScore: number,
  previousScore: number,
  historyScores: number[] = [],
): ScoreAnomalyEvaluation {
  const drop = previousScore - currentScore;
  if (drop < 10) {
    return { isAnomaly: false, drop };
  }

  let isAnomaly = false;
  let zScore: number | undefined;
  let mean: number | undefined;
  let stdDev: number | undefined;

  if (historyScores.length >= 3) {
    const stats = calculateScoreStats(historyScores);
    mean = stats.mean;
    stdDev = stats.stdDev;
    if (stdDev > 0) {
      zScore = Math.round(((mean - currentScore) / stdDev) * 100) / 100;
      if (zScore >= 2.0) {
        isAnomaly = true;
      }
    }
  }

  if (drop >= 15 || (drop >= 12 && currentScore < 50)) {
    isAnomaly = true;
  }

  if (!isAnomaly) {
    return { isAnomaly: false, drop, mean, stdDev, zScore };
  }

  let severity: FindingSeverity = FindingSeverity.MEDIUM;
  if (drop >= 25 || (drop >= 15 && currentScore < 40)) {
    severity = FindingSeverity.CRITICAL;
  } else if (drop >= 15 || (zScore !== undefined && zScore >= 2.5)) {
    severity = FindingSeverity.HIGH;
  }

  return { isAnomaly: true, drop, mean, stdDev, zScore, severity };
}


