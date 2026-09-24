import { FindingSeverity } from '@prisma/client';
import { FINDING_RULES, getRule, severityFromCvss } from './rules.catalog';

describe('rules.catalog', () => {
  it('la severidad de cada regla es coherente con su CVSS de referencia', () => {
    for (const rule of FINDING_RULES.values()) {
      expect(severityFromCvss(rule.cvss)).toBe(rule.severity);
      expect(rule.cvss).toBeGreaterThanOrEqual(0);
      expect(rule.cvss).toBeLessThanOrEqual(10);
      expect(rule.recommendation.length).toBeGreaterThan(10);
    }
  });

  it('mapea los rangos CVSS v3.1 a severidades', () => {
    expect(severityFromCvss(9.8)).toBe(FindingSeverity.CRITICAL);
    expect(severityFromCvss(7.0)).toBe(FindingSeverity.HIGH);
    expect(severityFromCvss(4.0)).toBe(FindingSeverity.MEDIUM);
    expect(severityFromCvss(0.1)).toBe(FindingSeverity.LOW);
    expect(severityFromCvss(0)).toBe(FindingSeverity.INFO);
  });

  it('rechaza reglas desconocidas', () => {
    expect(() => getRule('NO-EXISTE')).toThrow(/desconocida/);
  });
});
