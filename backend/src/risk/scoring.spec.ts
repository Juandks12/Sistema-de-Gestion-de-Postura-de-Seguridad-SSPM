import { aggregateScores, computeScore, describeModel, GRADE_BANDS, gradeFor, SEVERITY_CAPS, SEVERITY_WEIGHTS } from './scoring';

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
  });
});
