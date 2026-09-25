import { FindingSeverity } from '@prisma/client';

/**
 * Motor de riesgo y Security Score (RF-07), sección 6.3 del documento.
 *
 * Modelo de puntuación:
 *   Score = 100 - Σ min(Tope_s, Peso_s × N_s)   para cada severidad s
 *   acotado al rango [0, 100].
 *
 * - Solo cuentan los hallazgos en estado OPEN. Los ACCEPTED (riesgo aceptado),
 *   FALSE_POSITIVE y RESOLVED no penalizan.
 * - Los pesos derivan de la severidad CVSS v3.1 de cada regla (6.3.3): un solo
 *   hallazgo crítico deja la postura en 75 y cuatro la llevan a 0.
 * - Cada severidad tiene un tope de penalización (6.3.4) para que muchos
 *   hallazgos menores no oculten uno crítico ni hundan el score por sí solos.
 * - La calificación por letra (6.3.5) traduce el número a un nivel comprensible.
 *
 * Las constantes están aquí, en un único sitio, para poder ajustarlas tras el
 * caso de estudio (sección 13.4) sin tocar el resto del sistema.
 */

export const SCORING_MODEL_VERSION = '1.0';

/** Penalización por cada hallazgo abierto de la severidad. */
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
  modelVersion: string;
}

export function emptyCounts(): SeverityCounts {
  return { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
}

export function gradeFor(score: number): GradeBand {
  const band = GRADE_BANDS.find((b) => score >= b.min);
  return band ?? GRADE_BANDS[GRADE_BANDS.length - 1];
}

/** Calcula el Security Score a partir del conteo de hallazgos abiertos por severidad. */
export function computeScore(counts: Partial<SeverityCounts>): ScoreResult {
  const full: SeverityCounts = { ...emptyCounts(), ...counts };
  const penalties: SeverityPenalty[] = SEVERITY_ORDER.map((severity) => {
    const count = Math.max(0, Math.floor(full[severity] ?? 0));
    const weight = SEVERITY_WEIGHTS[severity];
    const cap = SEVERITY_CAPS[severity];
    const raw = weight * count;
    return { severity, count, weight, cap, penalty: Math.min(cap, raw), capped: raw > cap };
  });
  const totalPenalty = penalties.reduce((acc, p) => acc + p.penalty, 0);
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
    formula: 'score = clamp(100 - Σ min(cap[s], weight[s] × open[s]), 0, 100)',
    countsOnly: ['OPEN'],
    excluded: ['RESOLVED', 'ACCEPTED', 'FALSE_POSITIVE'],
    weights: SEVERITY_WEIGHTS,
    caps: SEVERITY_CAPS,
    organizationScore: 'media redondeada de los scores de los activos con al menos un escaneo completado',
    grades: GRADE_BANDS,
  };
}
