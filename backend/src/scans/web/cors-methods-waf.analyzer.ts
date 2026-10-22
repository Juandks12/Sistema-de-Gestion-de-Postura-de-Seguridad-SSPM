import { FindingDraft } from '../scanner.interface';
import { HeaderMap } from '../analyzers/headers.analyzer';
import { httpProbe, HttpProbeOptions } from './http-client';

export interface CorsMethodsWafAnalysisResult {
  findings: FindingDraft[];
  corsOriginReflected: boolean;
  dangerousMethodsAllowed: string[];
  wafDetected: boolean;
  wafProvider?: string;
}

const WAF_SIGNATURES: Array<{ provider: string; check: (headers: HeaderMap) => boolean }> = [
  {
    provider: 'Cloudflare',
    check: (h) => Boolean(h['cf-ray'] || h['cf-cache-status'] || String(h['server']).toLowerCase().includes('cloudflare')),
  },
  {
    provider: 'AWS CloudFront / AWS WAF',
    check: (h) => Boolean(h['x-amz-cf-id'] || h['x-amzn-waf-action'] || h['x-amzn-requestid']),
  },
  {
    provider: 'Akamai',
    check: (h) => Boolean(h['x-akamai-transformed'] || h['x-akamai-request-id'] || String(h['server']).toLowerCase().includes('akamai')),
  },
  {
    provider: 'Imperva / Incapsula',
    check: (h) => Boolean(h['x-iinfo'] || h['x-cdn'] === 'Incapsula'),
  },
  {
    provider: 'Fastly',
    check: (h) => Boolean(h['fastly-restarts'] || h['x-fastly-request-id']),
  },
  {
    provider: 'Sucuri CloudProxy',
    check: (h) => Boolean(h['x-sucuri-id'] || h['x-sucuri-cache']),
  },
];

/**
 * Evalúa sondas activas de CORS Origin Reflection, métodos HTTP peligrosos y presencia de WAF/CDN.
 */
export async function analyzeCorsMethodsAndWaf(
  baseUrl: string,
  homepageHeaders: HeaderMap,
  probeOptions: HttpProbeOptions,
  hasSensitiveFeatures = false,
): Promise<CorsMethodsWafAnalysisResult> {
  const findings: FindingDraft[] = [];
  const base = new URL(baseUrl);
  const location = `${base.protocol}//${base.host}/`;

  let corsOriginReflected = false;
  const dangerousMethodsAllowed: string[] = [];
  let wafDetected = false;
  let wafProvider: string | undefined;

  // 1. Sonda Activa de CORS Origin Reflection
  try {
    const arbitraryOrigin = 'https://sspm-probe.invalid';
    const corsProbe = await httpProbe(baseUrl, {
      ...probeOptions,
      method: 'GET',
      headers: {
        origin: arbitraryOrigin,
      },
      maxRedirects: 1,
      maxBodyBytes: 16 * 1024,
    });

    if (corsProbe.ok) {
      const h = corsProbe.headers;
      const acao = String(h['access-control-allow-origin'] ?? '').trim();
      const acac = String(h['access-control-allow-credentials'] ?? '').trim().toLowerCase();

      if (acao === arbitraryOrigin && acac === 'true') {
        corsOriginReflected = true;
        findings.push({
          ruleId: 'HDR-CORS-ORIGIN-REFLECTION',
          location,
          title: `CORS con reflexión arbitraria de origen y credenciales habilitadas (Riesgo Crítico de Robo de Sesión)`,
          evidence: {
            testedOrigin: arbitraryOrigin,
            reflectedOrigin: acao,
            allowCredentials: acac,
            impact: 'Un sitio web atacante puede realizar peticiones autenticadas y leer respuestas privadas de clientes del comercio.',
          },
        });
      }
    }
  } catch {
    // Ignorar fallo de sonda CORS
  }

  // 2. Sonda de Métodos HTTP Peligrosos (OPTIONS)
  try {
    const optionsProbe = await httpProbe(baseUrl, {
      ...probeOptions,
      method: 'OPTIONS',
      maxRedirects: 1,
      maxBodyBytes: 16 * 1024,
    });

    if (optionsProbe.ok) {
      const allowHeader = String(optionsProbe.headers['allow'] || optionsProbe.headers['access-control-allow-methods'] || '');
      const methods = allowHeader.split(',').map((m) => m.trim().toUpperCase());

      for (const dangerous of ['TRACE', 'TRACK', 'PUT', 'DELETE']) {
        if (methods.includes(dangerous)) {
          dangerousMethodsAllowed.push(dangerous);
        }
      }

      if (dangerousMethodsAllowed.length > 0) {
        findings.push({
          ruleId: 'WEB-HTTP-METHODS-DANGEROUS',
          location,
          title: `Métodos HTTP peligrosos habilitados públicamente (${dangerousMethodsAllowed.join(', ')})`,
          evidence: {
            allowedMethods: methods,
            dangerousMethodsAllowed,
            allowHeader,
          },
        });
      }
    }
  } catch {
    // Ignorar fallo de OPTIONS
  }

  // 3. Detección de WAF / CDN Protector
  const headersLower: HeaderMap = {};
  for (const [k, v] of Object.entries(homepageHeaders)) {
    headersLower[k.toLowerCase()] = v;
  }

  for (const sig of WAF_SIGNATURES) {
    if (sig.check(headersLower)) {
      wafDetected = true;
      wafProvider = sig.provider;
      break;
    }
  }

  // Si no se detecta WAF en un comercio con login/checkout, reportar recomendación preventiva
  if (!wafDetected && hasSensitiveFeatures) {
    findings.push({
      ruleId: 'WEB-WAF-ABSENT',
      location,
      title: `Ausencia de Web Application Firewall (WAF) o CDN protectora en el comercio`,
      evidence: {
        serverHeader: homepageHeaders['server'] ?? null,
        recommendation: 'Implemente un WAF (Cloudflare, AWS WAF, Imperva) para mitigar ataques DDoS, bots de scraping y exploits en capa 7.',
      },
    });
  }

  return {
    findings,
    corsOriginReflected,
    dangerousMethodsAllowed,
    wafDetected,
    wafProvider,
  };
}
