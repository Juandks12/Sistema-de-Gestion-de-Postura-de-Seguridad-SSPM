import { PathResponse, SENSITIVE_PATHS } from './sensitive-paths.catalog';
import { FINDING_RULES } from '../../findings/rules.catalog';

const response = (text: string, status = 200, contentType = 'text/plain'): PathResponse => ({
  status,
  contentType,
  body: Buffer.from(text),
  text,
});

const rule = (path: string) => SENSITIVE_PATHS.find((r) => r.path === path)!;

describe('SENSITIVE_PATHS', () => {
  it('todas las rutas referencian reglas del catálogo y son únicas', () => {
    const paths = SENSITIVE_PATHS.map((r) => r.path);
    expect(new Set(paths).size).toBe(paths.length);
    for (const r of SENSITIVE_PATHS) expect(FINDING_RULES.has(r.ruleId)).toBe(true);
  });

  it('las firmas exigen contenido real y no solo un 200', () => {
    expect(rule('/.env').signature(response('<html>Not found</html>'))).toBe(false);
    expect(rule('/.env').signature(response('APP_KEY=base64:abc\nDB_PASSWORD=secret'))).toBe(true);
    expect(rule('/.git/HEAD').signature(response('ref: refs/heads/main\n'))).toBe(true);
    expect(rule('/.git/HEAD').signature(response('<html>ok</html>'))).toBe(false);
    expect(rule('/backup.zip').signature({ ...response(''), body: Buffer.from([0x50, 0x4b, 0x03, 0x04, 0x00]) })).toBe(true);
    expect(rule('/phpinfo.php').signature(response('<h1>PHP Version 8.2.0</h1>', 200, 'text/html'))).toBe(true);
    expect(rule('/uploads/').signature(response('<title>Index of /uploads</title>', 200, 'text/html'))).toBe(true);
    expect(rule('/admin/').signature(response('<form><input type="password"></form>', 200, 'text/html'))).toBe(true);
    expect(rule('/admin/').signature(response('{"ok":true}', 200, 'application/json'))).toBe(false);
    expect(rule('/.kube/config').signature(response('apiVersion: v1\nclusters:\n- cluster:'))).toBe(true);
    expect(rule('/server.key').signature(response('-----BEGIN RSA PRIVATE KEY-----\nMIIE...'))).toBe(true);
    expect(rule('/_ignition/health-check').signature(response('{"can_execute_commands":false,"laravel":"10.0"}'))).toBe(true);
    expect(rule('/redoc').signature(response('<div id="redoc-container"></div>', 200, 'text/html'))).toBe(true);
    expect(rule('/actuator/prometheus').signature(response('# HELP jvm_memory_used_bytes\n# TYPE jvm_memory_used_bytes gauge'))).toBe(true);
  });
});
