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

  it('exige la verificación de propiedad de activos en producción', () => {
    expect(validateEnv({ ...base }).ASSET_VERIFICATION_REQUIRED).toBe(true);
    expect(validateEnv({ ...base, ASSET_VERIFICATION_REQUIRED: 'false' }).ASSET_VERIFICATION_REQUIRED).toBe(false);
    expect(() => validateEnv({ ...base, NODE_ENV: 'production', ASSET_VERIFICATION_REQUIRED: 'false' })).toThrow(
      /ASSET_VERIFICATION_REQUIRED/,
    );
  });

  it('valida TRUST_PROXY y los límites del inicio de sesión', () => {
    for (const ok of ['', '1', 'true', 'loopback', '10.0.0.0/8, 172.16.0.0/12']) {
      expect(validateEnv({ ...base, TRUST_PROXY: ok }).TRUST_PROXY).toBe(ok);
    }
    expect(() => validateEnv({ ...base, TRUST_PROXY: 'cualquiera; rm -rf' })).toThrow(/TRUST_PROXY/);
    expect(validateEnv({ ...base })).toMatchObject({ AUTH_MAX_FAILED_LOGINS: 5, AUTH_LOCKOUT_MINUTES: 15 });
    expect(() => validateEnv({ ...base, AUTH_MAX_FAILED_LOGINS: '1' })).toThrow();
  });
});
