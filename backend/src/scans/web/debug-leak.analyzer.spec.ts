import {
  inspectContentForDebugLeaks,
  probeAndAnalyzeDebugLeaks,
} from './debug-leak.analyzer';
import { httpProbe } from './http-client';

jest.mock('./http-client', () => ({
  ...jest.requireActual('./http-client'),
  httpProbe: jest.fn(),
}));

describe('DebugLeakAnalyzer', () => {
  const mockedHttpProbe = httpProbe as unknown as jest.Mock;

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('inspectContentForDebugLeaks', () => {
    it('detecta trazas de error de Node.js / Express y rutas internas Unix', () => {
      const errorBody = `
        Error: Cannot find module './secret-handler'
            at Function.Module._resolveFilename (node:internal/modules/cjs/loader:1144:15)
            at Function.Module._load (node:internal/modules/cjs/loader:985:27)
            at /var/www/backend/src/server.ts:42:12
      `;

      const result = inspectContentForDebugLeaks(errorBody, {}, 'https://example.com/api/test');
      expect(result.analyzed).toBe(true);
      expect(result.stackTraceDetected).toBe(true);
      expect(result.framework).toBe('Node.js / Express');
      expect(result.internalPathsDisclosed).toContain('/var/www/backend/src/server.ts');

      const traceFinding = result.findings.find((f) => f.ruleId === 'WEB-DEBUG-STACKTRACE-LEAK');
      expect(traceFinding).toBeDefined();

      const pathFinding = result.findings.find((f) => f.ruleId === 'WEB-INTERNAL-PATH-DISCLOSURE');
      expect(pathFinding).toBeDefined();
    });

    it('detecta trazas de Python / Django y rutas /app/src/ de contenedores', () => {
      const errorBody = `
        Traceback (most recent call last):
          File "/app/src/views/checkout.py", line 88, in process_payment
            gateway.charge(amount, token)
        ZeroDivisionError: division by zero
      `;

      const result = inspectContentForDebugLeaks(errorBody, {}, 'https://example.com/checkout');
      expect(result.stackTraceDetected).toBe(true);
      expect(result.framework).toMatch(/Python/);
      expect(result.internalPathsDisclosed).toContain('/app/src/views/checkout.py');
    });

    it('detecta errores de PHP con nombres de archivo en /home/ y Call Stack', () => {
      const errorBody = `
        Fatal error: Uncaught Error: Call to undefined function db_connect() in /home/admin/public_html/config.php on line 15
        Stack trace:
        #0 /home/admin/public_html/index.php(8): require()
      `;

      const result = inspectContentForDebugLeaks(errorBody, {}, 'https://example.com/index.php');
      expect(result.stackTraceDetected).toBe(true);
      expect(result.framework).toBe('PHP');
      expect(result.internalPathsDisclosed).toContain('/home/admin/public_html/config.php');
      expect(result.internalPathsDisclosed).toContain('/home/admin/public_html/index.php');
    });

    it('detecta páginas de error de ASP.NET con rutas de Windows', () => {
      const errorBody = `
        [NullReferenceException: Object reference not set to an instance of an object.]
           at System.Web.UI.TemplateControl.LoadControl() in C:\\inetpub\\wwwroot\\Global.asax.cs:line 45
        Server Error in '/' Application.
      `;

      const result = inspectContentForDebugLeaks(errorBody, {}, 'https://example.com/app');
      expect(result.stackTraceDetected).toBe(true);
      expect(result.framework).toMatch(/ASP\.NET/);
      expect(result.internalPathsDisclosed).toContain('C:\\inetpub\\wwwroot\\Global.asax.cs');
    });

    it('detecta cabecera X-Debug-Token de Symfony profiler', () => {
      const headers = {
        'x-debug-token': 'a9f24b',
        'x-debug-token-link': 'https://example.com/_profiler/a9f24b',
      };

      const result = inspectContentForDebugLeaks('Normal response', headers, 'https://example.com/');
      expect(result.stackTraceDetected).toBe(true);
      expect(result.framework).toBe('Symfony Profiler');
      expect(result.debugHeadersFound).toContain('x-debug-token');
      expect(result.findings.some((f) => f.ruleId === 'WEB-DEBUG-STACKTRACE-LEAK')).toBe(true);
    });

    it('no genera hallazgos en páginas de error limpias o normales', () => {
      const normalBody = '<html><body><h1>404 Not Found</h1><p>The page you requested was not found.</p></body></html>';
      const result = inspectContentForDebugLeaks(normalBody, { 'content-type': 'text/html' }, 'https://example.com/404');

      expect(result.stackTraceDetected).toBe(false);
      expect(result.internalPathsDisclosed).toHaveLength(0);
      expect(result.findings).toHaveLength(0);
    });
  });

  describe('probeAndAnalyzeDebugLeaks', () => {
    it('sondea rutas canary y agrega hallazgos encontrados', async () => {
      mockedHttpProbe
        // 1. Canary probe triggers stack trace
        .mockResolvedValueOnce({
          ok: true,
          status: 500,
          finalUrl: 'https://example.com/_sspm_debug_canary_1234',
          headers: {},
          body: Buffer.from(`
            java.lang.NullPointerException: null pointer
                at com.company.security.AuthController.login(AuthController.java:55)
          `),
        })
        // 2. Query probe returns clean 400
        .mockResolvedValueOnce({
          ok: true,
          status: 400,
          finalUrl: 'https://example.com/?_sspm_dbg=1',
          headers: {},
          body: Buffer.from('Bad Request'),
        });

      const outcome = await probeAndAnalyzeDebugLeaks('https://example.com', {
        allowPrivate: false,
        signal: new AbortController().signal,
      });

      expect(outcome.analyzed).toBe(true);
      expect(outcome.stackTraceDetected).toBe(true);
      expect(outcome.framework).toBe('Java / Spring');
      expect(outcome.findings).toHaveLength(1);
      expect(outcome.findings[0].ruleId).toBe('WEB-DEBUG-STACKTRACE-LEAK');
    });
  });
});
