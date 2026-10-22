import { FindingDraft } from '../scanner.interface';
import { httpProbe, HttpProbeOptions, HttpProbeResult } from './http-client';

export interface CrawledForm {
  action: string;
  method: string;
  hasPasswordInput: boolean;
  hasCardInput: boolean;
  inputs: Array<{ name?: string; type?: string }>;
}

export interface CrawledScript {
  src: string;
  isExternal: boolean;
  integrity?: string;
  crossorigin?: string;
}

export interface CrawledPage {
  url: string;
  status: number;
  html: string;
  contentType: string;
  scripts: CrawledScript[];
  forms: CrawledForm[];
  internalLinks: string[];
}

export interface CrawledSiteData {
  baseUrl: string;
  pages: CrawledPage[];
  robotsTxt: {
    found: boolean;
    disallows: string[];
    sensitiveExposed: string[];
    sitemaps: string[];
  };
  sitemapFound: boolean;
  findings: FindingDraft[];
}

const SENSITIVE_DISALLOW_PATTERNS = [
  /admin/i,
  /checkout/i,
  /cart|carrito/i,
  /factur|billing|invoice/i,
  /backup|copia/i,
  /staging|dev|test/i,
  /privat|secreto/i,
  /api\//i,
  /export|download/i,
  /upload/i,
  /cuenta|account/i,
];

const COMMERCIAL_PRIORITY_PATTERNS = [
  /checkout|finalizar-compra|pagar|pago|payment/i,
  /cart|carrito|cesta|bolsa/i,
  /login|signin|iniciar-sesion|acceso|auth|wp-login/i,
  /account|mi-cuenta|perfil|profile/i,
  /register|registro|signup/i,
  /admin|backend|administrator|gestion/i,
  /api\/|graphql/i,
  /contact|contacto/i,
];

function isSameOrigin(targetUrl: string, baseOrigin: string): boolean {
  try {
    const parsed = new URL(targetUrl);
    return parsed.origin.toLowerCase() === baseOrigin.toLowerCase();
  } catch {
    return false;
  }
}

export function extractLinksFromHtml(html: string, baseUrl: string): string[] {
  const links = new Set<string>();
  const base = new URL(baseUrl);
  const baseOrigin = base.origin;

  const hrefRegex = /<a\s+[^>]*?href=["']([^"']+)["']/gi;
  let match: RegExpExecArray | null;

  while ((match = hrefRegex.exec(html)) !== null) {
    const rawHref = match[1].trim();
    if (!rawHref || rawHref.startsWith('#') || rawHref.startsWith('javascript:') || rawHref.startsWith('mailto:') || rawHref.startsWith('tel:')) {
      continue;
    }
    try {
      const resolved = new URL(rawHref, baseUrl);
      if (resolved.origin.toLowerCase() === baseOrigin.toLowerCase() && (resolved.protocol === 'http:' || resolved.protocol === 'https:')) {
        // Normalizar eliminando fragmentos
        resolved.hash = '';
        links.add(resolved.toString());
      }
    } catch {
      // Ignorar URLs malformadas
    }
  }

  return Array.from(links);
}

export function extractScriptsFromHtml(html: string, baseUrl: string): CrawledScript[] {
  const scripts: CrawledScript[] = [];
  const base = new URL(baseUrl);
  const baseHost = base.hostname.toLowerCase();

  const scriptRegex = /<script\b([^>]*?)>(?:<\/script>)?/gi;
  let match: RegExpExecArray | null;

  while ((match = scriptRegex.exec(html)) !== null) {
    const attrs = match[1];
    const srcMatch = /src=["']([^"']+)["']/i.exec(attrs);
    if (!srcMatch) continue;

    const rawSrc = srcMatch[1].trim();
    if (!rawSrc || rawSrc.startsWith('data:') || rawSrc.startsWith('javascript:')) continue;

    try {
      const resolved = new URL(rawSrc, baseUrl);
      const isExternal = !resolved.hostname.toLowerCase().endsWith(baseHost) && !baseHost.endsWith(resolved.hostname.toLowerCase());
      const integrityMatch = /integrity=["']([^"']+)["']/i.exec(attrs);
      const crossOriginMatch = /crossorigin=["']?([^"'\s>]+)?/i.exec(attrs);

      scripts.push({
        src: resolved.toString(),
        isExternal,
        integrity: integrityMatch ? integrityMatch[1] : undefined,
        crossorigin: crossOriginMatch ? crossOriginMatch[1] : undefined,
      });
    } catch {
      // Ignorar URLs malformadas
    }
  }

  return scripts;
}

export function extractFormsFromHtml(html: string, baseUrl: string): CrawledForm[] {
  const forms: CrawledForm[] = [];
  const formRegex = /<form\b([^>]*?)>([\s\S]*?)<\/form>/gi;
  let formMatch: RegExpExecArray | null;

  while ((formMatch = formRegex.exec(html)) !== null) {
    const formAttrs = formMatch[1];
    const formInner = formMatch[2];

    const actionMatch = /action=["']([^"']*)["']/i.exec(formAttrs);
    const methodMatch = /method=["']([^"']*)["']/i.exec(formAttrs);

    let action = baseUrl;
    if (actionMatch && actionMatch[1].trim()) {
      try {
        action = new URL(actionMatch[1].trim(), baseUrl).toString();
      } catch {
        action = actionMatch[1].trim();
      }
    }

    const method = methodMatch ? methodMatch[1].trim().toUpperCase() : 'GET';
    const inputs: Array<{ name?: string; type?: string }> = [];

    const inputRegex = /<input\b([^>]*?)\/?>/gi;
    let inputMatch: RegExpExecArray | null;
    let hasPasswordInput = false;
    let hasCardInput = false;

    while ((inputMatch = inputRegex.exec(formInner)) !== null) {
      const inputAttrs = inputMatch[1];
      const typeMatch = /type=["']([^"']*)["']/i.exec(inputAttrs);
      const nameMatch = /name=["']([^"']*)["']/i.exec(inputAttrs);

      const type = typeMatch ? typeMatch[1].toLowerCase() : 'text';
      const name = nameMatch ? nameMatch[1] : undefined;

      if (type === 'password') hasPasswordInput = true;
      if (name && /(card|cc[-_]?num|cvv|cvc|exp[-_]?date|tarjeta)/i.test(name)) hasCardInput = true;

      inputs.push({ type, name });
    }

    forms.push({
      action,
      method,
      hasPasswordInput,
      hasCardInput,
      inputs,
    });
  }

  return forms;
}

/**
 * Rastrea de manera segura y delimitada un sitio de comercio electrónico:
 * 1. Lee `/robots.txt` e identifica rutas sensibles y sitemaps.
 * 2. Extrae enlaces internos relevantes de la portada y sitemap.
 * 3. Descarga y extrae scripts, formularios y metadatos de hasta `maxPages` URLs comerciales.
 */
export async function crawlEcommerceSite(
  baseUrl: string,
  initialResult: HttpProbeResult,
  probeOptions: HttpProbeOptions,
  maxPages = 15,
): Promise<CrawledSiteData> {
  const base = new URL(baseUrl);
  const baseOrigin = base.origin;
  const findings: FindingDraft[] = [];

  const initialHtml = initialResult.body.toString('utf8');
  const initialPage: CrawledPage = {
    url: initialResult.finalUrl,
    status: initialResult.status,
    html: initialHtml,
    contentType: initialResult.contentType,
    scripts: extractScriptsFromHtml(initialHtml, initialResult.finalUrl),
    forms: extractFormsFromHtml(initialHtml, initialResult.finalUrl),
    internalLinks: extractLinksFromHtml(initialHtml, initialResult.finalUrl),
  };

  const pagesMap = new Map<string, CrawledPage>();
  pagesMap.set(initialPage.url, initialPage);

  // 1. Parsear robots.txt
  const robotsData = {
    found: false,
    disallows: [] as string[],
    sensitiveExposed: [] as string[],
    sitemaps: [] as string[],
  };

  const robotsUrl = `${baseOrigin}/robots.txt`;
  const robotsProbe = await httpProbe(robotsUrl, {
    ...probeOptions,
    maxRedirects: 2,
    maxBodyBytes: 64 * 1024,
  });

  if (robotsProbe.ok && robotsProbe.status === 200) {
    const text = robotsProbe.body.toString('utf8');
    // Verificar que realmente sea un archivo de texto robots.txt y no una página HTML 404
    if (/User-agent:|Disallow:|Allow:|Sitemap:/i.test(text) && !/<html|<body/i.test(text)) {
      robotsData.found = true;
      const lines = text.split('\n');

      for (const line of lines) {
        const clean = line.split('#')[0].trim();
        const disallowMatch = /^Disallow:\s*(\S+)/i.exec(clean);
        const sitemapMatch = /^Sitemap:\s*(\S+)/i.exec(clean);

        if (disallowMatch) {
          const path = disallowMatch[1].trim();
          if (path && path !== '/') robotsData.disallows.push(path);
        }
        if (sitemapMatch) {
          robotsData.sitemaps.push(sitemapMatch[1].trim());
        }
      }

      // Detectar si robots.txt expone rutas sensibles de comercios
      const candidateSensitive = robotsData.disallows.filter((d) =>
        SENSITIVE_DISALLOW_PATTERNS.some((pattern) => pattern.test(d)),
      );

      // Probar las primeras 4 rutas sensibles declaradas para validar si responden 200/401/403
      for (const sensitivePath of candidateSensitive.slice(0, 4)) {
        const cleanPath = sensitivePath.startsWith('/') ? sensitivePath : `/${sensitivePath}`;
        const testUrl = `${baseOrigin}${cleanPath.replace(/\*$/, '')}`;
        const probeRes = await httpProbe(testUrl, {
          ...probeOptions,
          maxRedirects: 1,
          maxBodyBytes: 32 * 1024,
        });

        if (probeRes.ok && (probeRes.status === 200 || probeRes.status === 401 || probeRes.status === 403)) {
          robotsData.sensitiveExposed.push(cleanPath);
        }
      }

      if (robotsData.sensitiveExposed.length > 0) {
        findings.push({
          ruleId: 'PATH-ROBOTS-SENSITIVE-EXPOSED',
          location: robotsUrl,
          title: `El archivo robots.txt expone rutas sensibles o administrativas (${robotsData.sensitiveExposed.join(', ')})`,
          evidence: {
            robotsUrl,
            sensitiveExposed: robotsData.sensitiveExposed,
            disallowCount: robotsData.disallows.length,
          },
        });
      }
    }
  }

  // 2. Extraer candidatos del sitemap si existe
  const candidateUrls = new Set<string>();
  for (const link of initialPage.internalLinks) {
    candidateUrls.add(link);
  }

  let sitemapFound = false;
  const sitemapTarget = robotsData.sitemaps[0] || `${baseOrigin}/sitemap.xml`;
  const sitemapProbe = await httpProbe(sitemapTarget, {
    ...probeOptions,
    maxRedirects: 2,
    maxBodyBytes: 128 * 1024,
  });

  if (sitemapProbe.ok && sitemapProbe.status === 200 && /<urlset|<sitemapindex/i.test(sitemapProbe.body.toString('utf8'))) {
    sitemapFound = true;
    const sitemapText = sitemapProbe.body.toString('utf8');
    const locRegex = /<loc>([^<]+)<\/loc>/gi;
    let locMatch: RegExpExecArray | null;
    let count = 0;

    while ((locMatch = locRegex.exec(sitemapText)) !== null && count < 30) {
      const u = locMatch[1].trim();
      if (isSameOrigin(u, baseOrigin)) {
        candidateUrls.add(u);
        count++;
      }
    }
  }

  // 3. Priorizar URLs comerciales
  const prioritizedUrls: string[] = [];
  const secondaryUrls: string[] = [];

  for (const urlStr of candidateUrls) {
    if (pagesMap.has(urlStr)) continue;
    const isPriority = COMMERCIAL_PRIORITY_PATTERNS.some((p) => p.test(urlStr));
    if (isPriority) {
      prioritizedUrls.push(urlStr);
    } else {
      secondaryUrls.push(urlStr);
    }
  }

  const urlsToCrawl = [...prioritizedUrls, ...secondaryUrls].slice(0, maxPages - 1);

  // 4. Descargar páginas con límite de concurrencia de 3
  const concurrency = 3;
  for (let i = 0; i < urlsToCrawl.length; i += concurrency) {
    if (probeOptions.signal.aborted) break;
    const batch = urlsToCrawl.slice(i, i + concurrency);

    await Promise.all(
      batch.map(async (u) => {
        try {
          const res = await httpProbe(u, {
            ...probeOptions,
            maxRedirects: 2,
            maxBodyBytes: 128 * 1024,
          });

          if (res.ok && res.status >= 200 && res.status < 400 && res.contentType.includes('text/html')) {
            const html = res.body.toString('utf8');
            pagesMap.set(u, {
              url: res.finalUrl,
              status: res.status,
              html,
              contentType: res.contentType,
              scripts: extractScriptsFromHtml(html, res.finalUrl),
              forms: extractFormsFromHtml(html, res.finalUrl),
              internalLinks: extractLinksFromHtml(html, res.finalUrl),
            });
          }
        } catch {
          // Ignorar fallos puntuales de páginas secundarias
        }
      }),
    );
  }

  return {
    baseUrl,
    pages: Array.from(pagesMap.values()),
    robotsTxt: robotsData,
    sitemapFound,
    findings,
  };
}
