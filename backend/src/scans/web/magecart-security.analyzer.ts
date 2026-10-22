import { FindingDraft } from '../scanner.interface';
import { CrawledPage } from './ecommerce-crawler';

export interface MagecartAnalysisResult {
  findings: FindingDraft[];
  totalExternalScripts: number;
  scriptsMissingSri: string[];
  mixedContentUrls: string[];
  insecureFormsCount: number;
}

const CHECKOUT_PAYMENT_URL_RE = /checkout|finalizar-compra|pagar|pago|payment|onepage|cart|carrito/i;

/**
 * Evalúa riesgos de Magecart, E-Skimming, falta de Subresource Integrity (SRI)
 * y manipulación de formularios de pago según PCI-DSS v4.0 (Req. 6.4.3 y 11.6.1).
 */
export function analyzeMagecartAndFormSecurity(pages: CrawledPage[]): MagecartAnalysisResult {
  const findings: FindingDraft[] = [];
  const scriptsMissingSri = new Set<string>();
  const mixedContentUrls = new Set<string>();
  let totalExternalScripts = 0;
  let insecureFormsCount = 0;

  for (const page of pages) {
    const pageUrl = new URL(page.url);
    const isHttps = pageUrl.protocol === 'https:';
    const isCheckoutOrPayment = CHECKOUT_PAYMENT_URL_RE.test(page.url) || page.forms.some((f) => f.hasCardInput);

    // 1. Análisis de Subresource Integrity (SRI) en scripts externos
    for (const script of page.scripts) {
      if (!script.isExternal) continue;
      totalExternalScripts++;

      const hasValidSri =
        Boolean(script.integrity) &&
        (script.integrity!.startsWith('sha256-') ||
          script.integrity!.startsWith('sha384-') ||
          script.integrity!.startsWith('sha512-'));

      if (!hasValidSri) {
        scriptsMissingSri.add(script.src);

        findings.push({
          ruleId: 'WEB-SRI-MISSING-EXTERNAL-SCRIPT',
          location: `${page.url}#script:${script.src}`,
          title: isCheckoutOrPayment
            ? `Script externo sin integridad SRI en página de pago/checkout (Riesgo Magecart/Skimming - PCI-DSS v4.0)`
            : `Script externo de terceros cargado sin Subresource Integrity (SRI)`,
          evidence: {
            pageUrl: page.url,
            scriptUrl: script.src,
            isCheckoutOrPayment,
            integrityAttribute: script.integrity ?? null,
            standard: 'PCI-DSS v4.0 Req. 6.4.3 & 11.6.1 / OWASP Top 10 A08:2021',
          },
        });
      }
    }

    // 2. Análisis de Mixed Content (recursos HTTP dentro de HTTPS)
    if (isHttps) {
      // Buscar scripts, stylesheets, iframes sobre http://
      const activeMixedRegex = /<(?:script|iframe)\s+[^>]*?src=["'](http:\/\/[^"']+)["']/gi;
      let activeMatch: RegExpExecArray | null;

      while ((activeMatch = activeMixedRegex.exec(page.html)) !== null) {
        const insecureResource = activeMatch[1];
        mixedContentUrls.add(insecureResource);

        findings.push({
          ruleId: 'WEB-MIXED-CONTENT',
          location: `${page.url}#resource:${insecureResource}`,
          title: `Contenido mixto activo (HTTP sobre HTTPS) detectado (${insecureResource})`,
          evidence: {
            pageUrl: page.url,
            insecureResource,
            type: 'active',
          },
        });
      }
    }

    // 3. Formularios con acción insegura o envío en texto plano
    for (const form of page.forms) {
      const isSensitiveForm = form.hasPasswordInput || form.hasCardInput || isCheckoutOrPayment;

      if (isSensitiveForm) {
        let actionUrl: URL | null = null;
        try {
          actionUrl = new URL(form.action);
        } catch {
          // Ignorar URLs no parseables
        }

        // Si la página es HTTPS pero el formulario envía datos por HTTP
        if (actionUrl && isHttps && actionUrl.protocol === 'http:') {
          insecureFormsCount++;
          findings.push({
            ruleId: 'WEB-INSECURE-FORM-ACTION',
            location: `${page.url}#form:${form.action}`,
            title: `Formulario sensible envía credenciales o datos de pago a través de HTTP sin cifrado`,
            evidence: {
              pageUrl: page.url,
              formAction: form.action,
              method: form.method,
              hasPasswordInput: form.hasPasswordInput,
              hasCardInput: form.hasCardInput,
            },
          });
        }
      }
    }
  }

  return {
    findings,
    totalExternalScripts,
    scriptsMissingSri: Array.from(scriptsMissingSri),
    mixedContentUrls: Array.from(mixedContentUrls),
    insecureFormsCount,
  };
}
