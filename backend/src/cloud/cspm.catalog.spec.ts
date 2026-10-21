import { CloudProvider, FindingCategory } from '@prisma/client';
import { CSPM_RULES, CSPM_RULES_MAP } from './cspm.catalog';

describe('CSPM Catalog', () => {
  it('contiene las 31 reglas base de postura de seguridad cloud', () => {
    expect(CSPM_RULES).toHaveLength(31);
    expect(CSPM_RULES_MAP.size).toBe(31);
  });

  it('garantiza identificadores únicos para cada regla CSPM', () => {
    const ids = CSPM_RULES.map((r) => r.ruleId);
    const uniqueIds = new Set(ids);
    expect(uniqueIds.size).toBe(CSPM_RULES.length);
  });

  it('todas las reglas tienen puntuación CVSS válida entre 0.0 y 10.0', () => {
    for (const rule of CSPM_RULES) {
      expect(rule.cvssScore).toBeGreaterThanOrEqual(0);
      expect(rule.cvssScore).toBeLessThanOrEqual(10.0);
    }
  });

  it('cada regla posee guías de remediación en CLI e IaC (Terraform) y mapeo normativo', () => {
    for (const rule of CSPM_RULES) {
      expect(rule.title.trim().length).toBeGreaterThan(5);
      expect(rule.description.trim().length).toBeGreaterThan(10);
      expect(rule.recommendation.trim().length).toBeGreaterThan(10);
      expect(rule.remediationCli.trim().length).toBeGreaterThan(5);
      expect(rule.remediationIac.trim().length).toBeGreaterThan(5);
      expect(rule.complianceControlIds.length).toBeGreaterThan(0);
    }
  });

  it('cubre equilibradamente AWS y Azure en las 6 categorías de seguridad cloud', () => {
    const awsRules = CSPM_RULES.filter((r) => r.provider === CloudProvider.AWS);
    const azureRules = CSPM_RULES.filter((r) => r.provider === CloudProvider.AZURE);

    expect(awsRules.length).toBeGreaterThanOrEqual(15);
    expect(azureRules.length).toBeGreaterThanOrEqual(10);

    const categories = new Set(CSPM_RULES.map((r) => r.category));
    expect(categories.has(FindingCategory.CLOUD_IAM)).toBe(true);
    expect(categories.has(FindingCategory.CLOUD_STORAGE)).toBe(true);
    expect(categories.has(FindingCategory.CLOUD_NETWORK)).toBe(true);
    expect(categories.has(FindingCategory.CLOUD_COMPUTE)).toBe(true);
    expect(categories.has(FindingCategory.CLOUD_DATABASE)).toBe(true);
    expect(categories.has(FindingCategory.CLOUD_LOGGING)).toBe(true);
  });
});
