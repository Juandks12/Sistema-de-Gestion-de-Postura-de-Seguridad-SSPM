import { FindingDraft } from '../scanner.interface';
import { CrawledPage } from './ecommerce-crawler';
import { httpProbe, HttpProbeOptions } from './http-client';

export interface JsSecretsAnalysisResult {
  findings: FindingDraft[];
  scriptsAnalyzed: number;
  sourceMapsExposed: string[];
  secretsFoundCount: number;
}

interface SecretPattern {
  name: string;
  category: string;
  regex: RegExp;
  redact: (match: string) => string;
}

export function redactToken(val: string): string {
  if (val.length <= 8) return '****';
  return `${val.slice(0, 4)}****${val.slice(-4)}`;
}

const SECRET_PATTERNS: SecretPattern[] = [
  {
    name: 'Stripe Live Secret/Restricted Key',
    category: 'Pasarela de pago',
    regex: /(?:sk|rk)_live_[0-9a-zA-Z]{24,}/g,
    redact: redactToken,
  },
  {
    name: 'MercadoPago Access Token de Producción',
    category: 'Pasarela de pago',
    regex: /APP_USR-[0-9a-zA-Z]{12,}-[0-9a-zA-Z]{6,}-[0-9a-zA-Z_-]{20,}/g,
    redact: redactToken,
  },
  {
    name: 'Wompi Private Key de Producción',
    category: 'Pasarela de pago',
    regex: /prv_prod_[0-9a-zA-Z]{20,}/g,
    redact: redactToken,
  },
  {
    name: 'AWS Access Key ID',
    category: 'Infraestructura Cloud',
    regex: /(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])/g,
    redact: redactToken,
  },
  {
    name: 'Google API Key sin restricciones',
    category: 'API Externa',
    regex: /AIzaSy[0-9A-Za-z_-]{33}/g,
    redact: redactToken,
  },
  {
    name: 'Clave privada RSA/EC filtrada en frontend',
    category: 'Criptografía',
    regex: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/g,
    redact: () => '-----BEGIN PRIVATE KEY... [REDACTADO]',
  },
  {
    name: 'Token JWT quemado en código frontend',
    category: 'Autenticación',
    regex: /eyJ[a-zA-Z0-9_-]{15,}\.eyJ[a-zA-Z0-9_-]{15,}\.[a-zA-Z0-9_-]{10,}/g,
    redact: redactToken,
  },
];

/**
 * Inspecciona bundles JavaScript en busca de Source Maps expuestos (.js.map)
 * y credenciales o llaves privadas de pasarelas de pago y APIs en frontend.
 */
export async function analyzeJsSecretsAndSourceMaps(
  pages: CrawledPage[],
  probeOptions: HttpProbeOptions,
  maxScripts = 8,
): Promise<JsSecretsAnalysisResult> {
  const findings: FindingDraft[] = [];
  const sourceMapsExposed = new Set<string>();
  let secretsFoundCount = 0;

  // 1. Recolectar scripts únicos de las páginas
  const scriptUrls = new Set<string>();
  for (const page of pages) {
    for (const s of page.scripts) {
      if (s.src.endsWith('.js') || s.src.includes('.js?')) {
        scriptUrls.add(s.src);
      }
    }
  }

  const scriptsToInspect = Array.from(scriptUrls).slice(0, maxScripts);

  for (const scriptUrl of scriptsToInspect) {
    if (probeOptions.signal.aborted) break;

    try {
      const jsProbe = await httpProbe(scriptUrl, {
        ...probeOptions,
        maxRedirects: 2,
        maxBodyBytes: 256 * 1024,
      });

      if (!jsProbe.ok || jsProbe.status !== 200) continue;
      const jsContent = jsProbe.body.toString('utf8');

      // A. Detección de Source Maps expuestos (.js.map)
      let mapUrl: string | null = null;

      // Cabecera SourceMap / X-SourceMap
      const smHeader = jsProbe.headers['sourcemap'] || jsProbe.headers['x-sourcemap'];
      if (typeof smHeader === 'string' && smHeader.trim()) {
        try {
          mapUrl = new URL(smHeader.trim(), scriptUrl).toString();
        } catch {
          // Ignorar URL malformada
        }
      }

      // Comentario //# sourceMappingURL=...
      if (!mapUrl) {
        const commentMatch = /\/\/#\s*sourceMappingURL=([^\s"']+)/i.exec(jsContent);
        if (commentMatch && !commentMatch[1].startsWith('data:')) {
          try {
            mapUrl = new URL(commentMatch[1].trim(), scriptUrl).toString();
          } catch {
            // Ignorar
          }
        }
      }

      // Probar sufijo .map por defecto si no venía declarado
      if (!mapUrl && !scriptUrl.includes('?')) {
        mapUrl = `${scriptUrl}.map`;
      }

      if (mapUrl) {
        try {
          const mapProbe = await httpProbe(mapUrl, {
            ...probeOptions,
            maxRedirects: 1,
            maxBodyBytes: 64 * 1024,
          });

          if (mapProbe.ok && mapProbe.status === 200) {
            const mapText = mapProbe.body.toString('utf8');
            if (/"version"\s*:\s*3/.test(mapText) && /"sources"\s*:\s*\[/.test(mapText)) {
              sourceMapsExposed.add(mapUrl);

              findings.push({
                ruleId: 'PATH-SOURCEMAP-EXPOSED',
                location: mapUrl,
                title: `Archivo Source Map (.js.map) accesible en producción expone código fuente original`,
                evidence: {
                  scriptUrl,
                  mapUrl,
                  hasVersion3: true,
                  recommendation: 'Elimine los archivos .map en el build de producción o restrinja el acceso con firewall.',
                },
              });
            }
          }
        } catch {
          // Ignorar fallo de descarga del map
        }
      }

      // B. Búsqueda de Secretos y Llaves en el código JavaScript
      for (const pattern of SECRET_PATTERNS) {
        pattern.regex.lastIndex = 0;
        const matches = jsContent.match(pattern.regex);

        if (matches && matches.length > 0) {
          const redactedMatches = Array.from(new Set(matches)).map(pattern.redact);
          secretsFoundCount += matches.length;

          findings.push({
            ruleId: 'WEB-JS-SECRET-LEAK',
            location: `${scriptUrl}#secret:${pattern.name}`,
            title: `Fuga de credencial o secreto en bundle JavaScript frontend (${pattern.name})`,
            evidence: {
              scriptUrl,
              secretType: pattern.name,
              category: pattern.category,
              redactedMatches,
              matchesCount: matches.length,
            },
          });
        }
      }
    } catch {
      // Ignorar fallos de scripts individuales
    }
  }

  return {
    findings,
    scriptsAnalyzed: scriptsToInspect.length,
    sourceMapsExposed: Array.from(sourceMapsExposed),
    secretsFoundCount,
  };
}
