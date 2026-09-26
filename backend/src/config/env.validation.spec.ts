import 'reflect-metadata';
import { validateEnv } from './env.validation';

const base = {
  DATABASE_URL: 'postgresql://u:p@localhost:5432/db',
  JWT_SECRET: 'un-secreto-suficientemente-largo',
};

describe('validateEnv', () => {
  it('interpreta correctamente los booleanos escritos como texto', () => {
    expect(validateEnv({ ...base, ALLOW_PRIVATE_TARGETS: 'false' }).ALLOW_PRIVATE_TARGETS).toBe(false);
    expect(validateEnv({ ...base, ALLOW_PRIVATE_TARGETS: 'true' }).ALLOW_PRIVATE_TARGETS).toBe(true);
    expect(validateEnv({ ...base, SCAN_WORKER_ENABLED: '0' }).SCAN_WORKER_ENABLED).toBe(false);
    expect(validateEnv({ ...base }).ALLOW_PRIVATE_TARGETS).toBe(false);
  });

  it('convierte números y aplica valores por defecto', () => {
    const env = validateEnv({ ...base, SCAN_MAX_CONCURRENCY: '3' });
    expect(env.SCAN_MAX_CONCURRENCY).toBe(3);
    expect(env.SCAN_TIMEOUT_SECONDS).toBe(600);
  });

  it('rechaza el modo laboratorio en producción', () => {
    expect(() =>
      validateEnv({ ...base, NODE_ENV: 'production', ALLOW_PRIVATE_TARGETS: 'true' }),
    ).toThrow(/ALLOW_PRIVATE_TARGETS/);
  });

  it('valida los puertos web', () => {
    expect(validateEnv({ ...base }).WEB_HTTPS_PORTS).toBe('443');
    expect(validateEnv({ ...base, WEB_HTTP_PORTS: '80,8080' }).WEB_HTTP_PORTS).toBe('80,8080');
    expect(() => validateEnv({ ...base, WEB_HTTP_PORTS: '80-90' })).toThrow(/WEB_HTTP_PORTS/);
  });

  it('rechaza listas de puertos mal formadas', () => {
    expect(() => validateEnv({ ...base, SCAN_PORTS: '22;rm -rf' })).toThrow(/SCAN_PORTS/);
    expect(validateEnv({ ...base, SCAN_PORTS: '22,80,8000-8100' }).SCAN_PORTS).toBe('22,80,8000-8100');
  });

  it('aplica los valores por defecto de monitoreo y alertas', () => {
    const env = validateEnv({ ...base });
    expect(env.SCHEDULER_ENABLED).toBe(true);
    expect(env.SCHEDULER_INTERVAL_MS).toBe(60000);
    expect(env.SMTP_HOST).toBe('');
    expect(env.SMTP_PORT).toBe(587);
    expect(env.SMTP_SECURE).toBe(false);
    expect(validateEnv({ ...base, SCHEDULER_ENABLED: 'false', SMTP_SECURE: 'true' })).toMatchObject({
      SCHEDULER_ENABLED: false,
      SMTP_SECURE: true,
    });
    expect(() => validateEnv({ ...base, SCHEDULER_INTERVAL_MS: '10' })).toThrow();
  });
});
