import { FindingDraft } from '../scanner.interface';

export type HeaderMap = Record<string, string | string[] | undefined>;

export interface HeadersAnalysisInput {
  /** URL final tras seguir redirecciones. */
  finalUrl: string;
  status: number;
  headers: HeaderMap;
  /** true si el sitio también responde por HTTPS (para evaluar la redirección HTTP→HTTPS). */
  httpsAvailable?: boolean;
}

const SECURITY_HEADERS = [
  'strict-transport-security',
  'content-security-policy',
  'x-frame-options',
  'x-content-type-options',
  'referrer-policy',
  'permissions-policy',
] as const;

function first(value: string | string[] | undefined): string | undefined {
  if (Array.isArray(value)) return value[0];
  return value;
}

function all(value: string | string[] | undefined): string[] {
  if (value === undefined) return [];
  return Array.isArray(value) ? value : [value];
}

const VERSION_RE = /\d+\.\d+/;
const SESSION_COOKIE_RE = /sess|sid|token|auth|jwt|login|remember/i;

/**
 * Evalúa las cabeceras de seguridad de una respuesta HTTP (RF-04).
 * Función pura: no realiza peticiones.
 */
export function analyzeHeaders(input: HeadersAnalysisInput): FindingDraft[] {
  const url = new URL(input.finalUrl);
  const isHttps = url.protocol === 'https:';
  const location = `${url.protocol}//${url.host}/`;
  const headers: HeaderMap = {};
  for (const [k, v] of Object.entries(input.headers)) headers[k.toLowerCase()] = v;

  const findings: FindingDraft[] = [];
  const present = SECURITY_HEADERS.filter((h) => headers[h] !== undefined);
  const missing = SECURITY_HEADERS.filter((h) => headers[h] === undefined);
  const base = { present, missing, status: input.status, finalUrl: input.finalUrl };

  if (!isHttps && input.httpsAvailable) {
    findings.push({
      ruleId: 'HDR-HTTP-NO-REDIRECT',
      location,
      evidence: { ...base },
    });
  }

  // Las cabeceras de transporte solo aplican a HTTPS.
  if (isHttps) {
    const hsts = first(headers['strict-transport-security']);
    if (hsts === undefined) {
      findings.push({ ruleId: 'HDR-HSTS-MISSING', location, evidence: base });
    } else {
      const maxAge = Number(/max-age=(\d+)/i.exec(hsts)?.[1] ?? NaN);
      if (!Number.isFinite(maxAge) || maxAge < 15552000) {
        findings.push({
          ruleId: 'HDR-HSTS-SHORT',
          location,
          evidence: { ...base, header: hsts, maxAge: Number.isFinite(maxAge) ? maxAge : null },
        });
      }
    }
  }

  const csp = first(headers['content-security-policy']);
  if (csp === undefined) {
    findings.push({ ruleId: 'HDR-CSP-MISSING', location, evidence: base });
  } else {
    const unsafe = ['unsafe-inline', 'unsafe-eval'].filter((d) => csp.includes(d));
    const wildcard = /(default-src|script-src)[^;]*\s\*(\s|;|$)/.test(` ${csp}`);
    if (unsafe.length > 0 || wildcard) {
      findings.push({
        ruleId: 'HDR-CSP-UNSAFE',
        location,
        evidence: { ...base, header: csp.slice(0, 500), unsafeDirectives: unsafe, wildcard },
      });
    }
  }

  const xfo = first(headers['x-frame-options']);
  const frameAncestors = csp !== undefined && /frame-ancestors/i.test(csp);
  if (xfo === undefined && !frameAncestors) {
    findings.push({ ruleId: 'HDR-XFO-MISSING', location, evidence: base });
  }

  const xcto = first(headers['x-content-type-options']);
  if (xcto === undefined || !/nosniff/i.test(xcto)) {
    findings.push({ ruleId: 'HDR-XCTO-MISSING', location, evidence: { ...base, header: xcto ?? null } });
  }

  if (headers['referrer-policy'] === undefined) {
    findings.push({ ruleId: 'HDR-REFERRER-MISSING', location, evidence: base });
  }

  if (headers['permissions-policy'] === undefined) {
    findings.push({ ruleId: 'HDR-PERMISSIONS-MISSING', location, evidence: base });
  }

  const server = first(headers['server']);
  if (server !== undefined && VERSION_RE.test(server)) {
    findings.push({ ruleId: 'HDR-SERVER-VERSION', location, evidence: { ...base, header: server } });
  }

  const poweredBy = first(headers['x-powered-by']);
  if (poweredBy !== undefined) {
    findings.push({ ruleId: 'HDR-POWERED-BY', location, evidence: { ...base, header: poweredBy } });
  }

  for (const cookie of all(headers['set-cookie'])) {
    const name = cookie.split('=')[0]?.trim() ?? 'cookie';
    const attrs = cookie.toLowerCase();
    const cookieLocation = `${location}#cookie:${name}`;
    if (isHttps && !/;\s*secure(\s*;|\s*$)/.test(attrs)) {
      findings.push({
        ruleId: 'HDR-COOKIE-INSECURE',
        location: cookieLocation,
        title: `La cookie "${name}" no tiene el atributo Secure`,
        evidence: { ...base, cookie: name },
      });
    }
    if (SESSION_COOKIE_RE.test(name) && !/;\s*httponly(\s*;|\s*$)/.test(attrs)) {
      findings.push({
        ruleId: 'HDR-COOKIE-NO-HTTPONLY',
        location: cookieLocation,
        title: `La cookie "${name}" no tiene el atributo HttpOnly`,
        evidence: { ...base, cookie: name },
      });
    }
  }

  return findings;
}
