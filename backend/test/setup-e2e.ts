// Variables de entorno para las pruebas e2e (tienen prioridad sobre .env).
process.env.NODE_ENV = 'test';
process.env.SCAN_WORKER_ENABLED = 'true';
process.env.SCAN_POLL_INTERVAL_MS = '500';
process.env.SCAN_MAX_CONCURRENCY = '2';
process.env.SCAN_MAX_CONCURRENCY_PER_ORG = '1';
process.env.SCAN_MAX_PER_HOUR_PER_ORG = '100';
process.env.ALLOW_PRIVATE_TARGETS = 'false';
// El planificador se invoca explícitamente en las pruebas (MonitoringScheduler.runOnce).
process.env.SCHEDULER_ENABLED = 'false';
process.env.SMTP_HOST = '';
// Las suites anteriores escanean activos sin verificar; la verificación se prueba en asset-verification.e2e-spec.ts.
process.env.ASSET_VERIFICATION_REQUIRED = 'false';
// Cada suite registra varias organizaciones desde 127.0.0.1; los límites se prueban en auth-protection.e2e-spec.ts.
process.env.AUTH_LOGIN_RATE_PER_MINUTE = '1000';
process.env.AUTH_REGISTER_RATE_PER_HOUR = '1000';
