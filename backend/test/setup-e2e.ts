// Variables de entorno para las pruebas e2e (tienen prioridad sobre .env).
process.env.NODE_ENV = 'test';
process.env.SCAN_WORKER_ENABLED = 'true';
process.env.SCAN_POLL_INTERVAL_MS = '500';
process.env.SCAN_MAX_CONCURRENCY = '2';
process.env.SCAN_MAX_CONCURRENCY_PER_ORG = '1';
process.env.SCAN_MAX_PER_HOUR_PER_ORG = '100';
process.env.ALLOW_PRIVATE_TARGETS = 'false';
