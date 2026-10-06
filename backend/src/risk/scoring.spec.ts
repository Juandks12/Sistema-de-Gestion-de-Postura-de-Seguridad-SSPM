import { AssetCriticality } from '@prisma/client';
import {
  aggregateScores,
  computeHybridRisk,
  computeScore,
  CRITICALITY_FACTORS,
  describeModel,
  GRADE_BANDS,
  gradeFor,
  SEVERITY_CAPS,
  SEVERITY_WEIGHTS,
} from './scoring';

describe('scoring', () => {
  it('sin hallazgos abiertos la postura es 100 / A', () => {
    const r = computeScore({});
    expect(r.score).toBe(100);
    expect(r.grade).toBe('A');
    expect(r.totalPenalty).toBe(0);
  });

  it('aplica la fórmula documentada: 100 - Σ peso × cantidad', () => {
    const r = computeScore({ CRITICAL: 1, HIGH: 2, MEDIUM: 3, LOW: 4, INFO: 10 });
    const expected = 100 - (25 * 1 + 10 * 2 + 4 * 3 + 1 * 4 + 0 * 10);
    expect(r.score).toBe(expected);
    expect(r.score).toBe(39);
    expect(r.grade).toBe('F');
    expect(r.penalties.find((p) => p.severity === 'INFO')!.penalty).toBe(0);
  });

  it('limita la penalización por severidad con un tope', () => {
    const many = computeScore({ LOW: 50 });
    expect(many.score).toBe(100 - SEVERITY_CAPS.LOW);
    expect(many.penalties.find((p) => p.severity === 'LOW')).toMatchObject({ penalty: 10, capped: true });

    const mediums = computeScore({ MEDIUM: 20 });
    expect(mediums.score).toBe(70);
    expect(mediums.grade).toBe('C');
  });

  it('nunca baja de 0 ni supera 100', () => {
    expect(computeScore({ CRITICAL: 10, HIGH: 10, MEDIUM: 10 }).score).toBe(0);
    expect(computeScore({ CRITICAL: -3 }).score).toBe(100);
  });

  it('un solo hallazgo crítico deja la postura en B y cuatro en F', () => {
    expect(computeScore({ CRITICAL: 1 })).toMatchObject({ score: 75, grade: 'B' });
    expect(computeScore({ CRITICAL: 4 })).toMatchObject({ score: 0, grade: 'F' });
  });

  it('clasifica por bandas de calificación en los límites', () => {
    expect(gradeFor(90).grade).toBe('A');
    expect(gradeFor(89).grade).toBe('B');
    expect(gradeFor(75).grade).toBe('B');
    expect(gradeFor(60).grade).toBe('C');
    expect(gradeFor(40).grade).toBe('D');
    expect(gradeFor(39).grade).toBe('F');
    expect(GRADE_BANDS.map((b) => b.grade)).toEqual(['A', 'B', 'C', 'D', 'F']);
  });

  it('agrega el score de la organización como media redondeada', () => {
    expect(aggregateScores([])).toBeNull();
    expect(aggregateScores([100, 75])).toBe(88);
    expect(aggregateScores([0, 0, 100])).toBe(33);
  });

  it('describe el modelo con pesos y topes coherentes', () => {
    const m = describeModel();
    expect(m.weights).toEqual(SEVERITY_WEIGHTS);
    for (const s of Object.keys(SEVERITY_WEIGHTS) as Array<keyof typeof SEVERITY_WEIGHTS>) {
      expect(SEVERITY_CAPS[s]).toBeGreaterThanOrEqual(SEVERITY_WEIGHTS[s]);
    }
    expect(m.criticalityFactors).toEqual(CRITICALITY_FACTORS);
  });

  describe('ponderación por criticidad del activo', () => {
    it('penaliza con factor 1.5x en activos CRITICAL', () => {
      // 1 hallazgo CRITICAL en activo CRITICAL: 25 * 1.5 = 37.5 -> penalización 38 -> score 62
      const res = computeScore({ CRITICAL: 1 }, AssetCriticality.CRITICAL);
      expect(res.criticalityFactor).toBe(1.5);
      expect(res.totalPenalty).toBe(38);
      expect(res.score).toBe(62);
      expect(res.grade).toBe('C');
    });

    it('penaliza con factor 0.75x en activos LOW', () => {
      // 1 hallazgo HIGH (peso 10) en activo LOW: 10 * 0.75 = 7.5 -> penalización 8 -> score 92
      const res = computeScore({ HIGH: 1 }, AssetCriticality.LOW);
      expect(res.criticalityFactor).toBe(0.75);
      expect(res.totalPenalty).toBe(8);
      expect(res.score).toBe(92);
      expect(res.grade).toBe('A');
    });
  });

  describe('fórmula de riesgo híbrida: Riesgo = CVSS * (1 + EPSS) * FactorCriticidad', () => {
    it('calcula riesgo con CVSS base cuando EPSS es 0 y criticidad MEDIUM', () => {
      const risk = computeHybridRisk(7.5, 0, AssetCriticality.MEDIUM);
      expect(risk).toBe(7.5);
    });

    it('amplifica el riesgo cuando existe alta probabilidad EPSS', () => {
      // CVSS 7.0 con EPSS 0.94 en activo MEDIUM: 7.0 * (1 + 0.94) * 1.0 = 13.58
      const risk = computeHybridRisk(7.0, 0.94, AssetCriticality.MEDIUM);
      expect(risk).toBe(13.58);
    });

    it('pondera simultáneamente EPSS y criticidad del activo', () => {
      // CVSS 7.0 con EPSS 0.50 en activo CRITICAL (1.5): 7.0 * 1.5 * 1.5 = 15.75
      const risk = computeHybridRisk(7.0, 0.5, AssetCriticality.CRITICAL);
      expect(risk).toBe(15.75);
    });

    it('acota valores fuera de rango para CVSS y EPSS', () => {
      // CVSS > 10 se acota a 10, EPSS > 1 se acota a 1
      const risk = computeHybridRisk(15, 2.5, AssetCriticality.MEDIUM);
      // 10 * (1 + 1) * 1 = 20
      expect(risk).toBe(20);
    });
  });
});
