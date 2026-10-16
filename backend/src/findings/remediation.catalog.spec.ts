import { getRemediationGuide } from './remediation.catalog';

describe('remediation.catalog', () => {
  it('devuelve guía completa con snippets para reglas conocidas', () => {
    const hsts = getRemediationGuide('HDR-HSTS-MISSING');
    expect(hsts.ruleId).toBe('HDR-HSTS-MISSING');
    expect(hsts.owasp).toContain('A05:2021');
    expect(hsts.snippets.length).toBeGreaterThanOrEqual(2);
    expect(hsts.snippets.some((s) => s.platform === 'Nginx')).toBe(true);
    expect(hsts.verificationCommand).toContain('curl');

    const actuator = getRemediationGuide('API-ACTUATOR-ENV-EXPOSED');
    expect(actuator.ruleId).toBe('API-ACTUATOR-ENV-EXPOSED');
    expect(actuator.snippets.some((s) => s.platform === 'Spring Boot')).toBe(true);

    const swagger = getRemediationGuide('API-SWAGGER-EXPOSED');
    expect(swagger.snippets.length).toBeGreaterThan(0);

    const cors = getRemediationGuide('HDR-CORS-WILDCARD');
    expect(cors.ruleId).toBe('HDR-CORS-WILDCARD');
    expect(cors.snippets.some((s) => s.platform === 'Nginx')).toBe(true);

    const cookie = getRemediationGuide('HDR-COOKIE-INSECURE');
    expect(cookie.ruleId).toBe('HDR-COOKIE-INSECURE');
    expect(cookie.snippets.some((s) => s.platform === 'Spring Boot')).toBe(true);
  });

  it('devuelve guía fallback para reglas sin plantilla estática', () => {
    const unknown = getRemediationGuide('CUSTOM-UNKNOWN-RULE', 'Recomendación alternativa');
    expect(unknown.ruleId).toBe('CUSTOM-UNKNOWN-RULE');
    expect(unknown.summary).toBe('Recomendación alternativa');
    expect(unknown.snippets[0].code).toBe('Recomendación alternativa');
  });
});
