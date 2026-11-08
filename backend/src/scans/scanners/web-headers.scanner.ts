import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { ScanType } from '@prisma/client';
import { analyzeHeaders } from '../analyzers/headers.analyzer';
import { ScanExecutionError } from '../scan.errors';
import { abortReason, FindingDraft, ScanContext, Scanner, ScanOutcome, requireTarget } from '../scanner.interface';
import { httpProbe, HttpProbeOutcome, HttpProbeResult } from '../web/http-client';
import { DetectedTechnology, fingerprintTechnologies } from '../web/tech-fingerprint';
import { webTargetsFor } from './web-targets';
import { crawlEcommerceSite, CrawledSiteData } from '../web/ecommerce-crawler';
import { analyzeMagecartAndFormSecurity, MagecartAnalysisResult } from '../web/magecart-security.analyzer';
import { analyzeJsSecretsAndSourceMaps, JsSecretsAnalysisResult } from '../web/js-secrets-sourcemap.analyzer';
import { analyzeCmsAndEcommercePlatform, CmsEcommerceAnalysisResult } from '../web/cms-ecommerce.analyzer';
import { analyzeCorsMethodsAndWaf, CorsMethodsWafAnalysisResult } from '../web/cors-methods-waf.analyzer';
import { analyzeSecurityTxt, SecurityTxtAnalysisResult } from '../web/security-txt.analyzer';
import { probeAndAnalyzeOpenApi, OpenApiAnalysisResult } from '../web/openapi-security.analyzer';
import { probeAndAnalyzeDebugLeaks, DebugLeakAnalysisResult } from '../web/debug-leak.analyzer';

/** RF-04: auditoría de cabeceras HTTP de seguridad, fingerprinting tecnológico e inspección profunda de comercio electrónico. */
@Injectable()
export class WebHeadersScanner implements Scanner {
  readonly type = ScanType.WEB_HEADERS;

  constructor(private readonly config: ConfigService) {}

  async run(ctx: ScanContext): Promise<ScanOutcome> {
    const timeoutMs = this.config.get<number>('WEB_REQUEST_TIMEOUT_MS') ?? 10000;
    const targets = webTargetsFor(ctx.asset.value, ctx.openPorts, this.config);
    const probes: Array<{ target: (typeof targets)[number]; outcome: HttpProbeOutcome }> = [];

    for (const target of targets) {
      if (abortReason(ctx.signal)) throw new ScanExecutionError('Escaneo interrumpido');
      const outcome = await httpProbe(target.url, {
        allowPrivate: ctx.allowPrivate,
        signal: ctx.signal,
        timeoutMs,
        pinnedAddress: requireTarget(ctx).address,
        maxBodyBytes: 64 * 1024,
      });
      probes.push({ target, outcome });
    }

    const reachable = probes.filter(
      (p): p is { target: (typeof targets)[number]; outcome: HttpProbeResult } => p.outcome.ok,
    );
    if (reachable.length === 0) {
      throw new ScanExecutionError(
        `Ningún servicio web respondió en ${targets.map((t) => t.url).join(', ')}`,
      );
    }

    const httpsAvailable = reachable.some((p) => p.outcome.ok && new URL(p.outcome.finalUrl).protocol === 'https:');
    const findings: FindingDraft[] = [];
    const audited: Record<string, unknown>[] = [];
    const allTechnologies: DetectedTechnology[] = [];

    for (const { target, outcome } of probes) {
      if (!outcome.ok) {
        audited.push({ url: target.url, reachable: false, error: outcome.error, code: outcome.code ?? null });
        continue;
      }
      const isPlainHttpWhenHttpsAvailable =
        httpsAvailable && new URL(outcome.finalUrl).protocol === 'http:';
      const rawDrafts = analyzeHeaders({
        finalUrl: outcome.finalUrl,
        status: outcome.status,
        headers: outcome.headers,
        httpsAvailable,
      });
      // Cuando HTTPS está activo y accesible, la sonda HTTP en texto plano solo debe reportar
      // la ausencia de redirección a HTTPS (HDR-HTTP-NO-REDIRECT), evitando duplicar todas las
      // cabeceras faltantes (CSP, XFO, XCTO, Referrer, Permissions) en http:// y https://.
      const drafts = isPlainHttpWhenHttpsAvailable
        ? rawDrafts.filter((d) => d.ruleId === 'HDR-HTTP-NO-REDIRECT')
        : rawDrafts;

      const techResult = fingerprintTechnologies({
        finalUrl: outcome.finalUrl,
        status: outcome.status,
        headers: outcome.headers,
        bodyText: outcome.body.toString('utf8'),
      });
      const techFindings = isPlainHttpWhenHttpsAvailable ? [] : techResult.findings;

      findings.push(...drafts, ...techFindings);
      allTechnologies.push(...techResult.technologies);

      audited.push({
        url: target.url,
        reachable: true,
        finalUrl: outcome.finalUrl,
        status: outcome.status,
        redirects: outcome.hops.length - 1,
        findings: drafts.length + techFindings.length,
        technologies: techResult.technologies,
        headers: Object.fromEntries(
          Object.entries(outcome.headers).filter(([k]) => k !== 'set-cookie'),
        ),
        cookies: ([] as string[]).concat(outcome.headers['set-cookie'] ?? []).map((c) => c.split('=')[0]),
      });
    }

    // Análisis profundo de Comercio Electrónico, Magecart, Secretos JS, CMS y CORS/WAF
    let crawlResult: CrawledSiteData | null = null;
    let magecartResult: MagecartAnalysisResult | null = null;
    let jsSecretsResult: JsSecretsAnalysisResult | null = null;
    let cmsResult: CmsEcommerceAnalysisResult | null = null;
    let corsWafResult: CorsMethodsWafAnalysisResult | null = null;
    let securityTxtResult: SecurityTxtAnalysisResult | null = null;
    let openApiResult: OpenApiAnalysisResult | null = null;
    let debugLeakResult: DebugLeakAnalysisResult | null = null;

    const primary = reachable.find((p) => new URL(p.outcome.finalUrl).protocol === 'https:') ?? reachable[0];
    if (primary && primary.outcome.ok) {
      const probeOptions = {
        allowPrivate: ctx.allowPrivate,
        signal: ctx.signal,
        timeoutMs,
        pinnedAddress: requireTarget(ctx).address,
      };

      try {
        // 1. Crawler comercial seguro y delimitado
        crawlResult = await crawlEcommerceSite(primary.outcome.finalUrl, primary.outcome, probeOptions, 15);
        findings.push(...crawlResult.findings);

        // 2. Anti-Skimming / Magecart y Formularios PCI-DSS v4.0
        magecartResult = analyzeMagecartAndFormSecurity(crawlResult.pages);
        findings.push(...magecartResult.findings);

        // 3. Inspección de bundles JS, Source Maps (.js.map) y llaves de pasarelas de pago
        jsSecretsResult = await analyzeJsSecretsAndSourceMaps(crawlResult.pages, probeOptions, 8);
        findings.push(...jsSecretsResult.findings);

        // 4. Analizador de plataformas CMS / WooCommerce y APIs
        cmsResult = await analyzeCmsAndEcommercePlatform(primary.outcome.finalUrl, probeOptions);
        findings.push(...cmsResult.findings);

        // 5. Sondaje activo de CORS Origin Reflection, métodos peligrosos y WAF
        const hasSensitiveFeatures =
          crawlResult.pages.some((p) => p.forms.some((f) => f.hasPasswordInput || f.hasCardInput)) ||
          crawlResult.robotsTxt.disallows.some((d) => /checkout|cart|login|admin/i.test(d));
        corsWafResult = await analyzeCorsMethodsAndWaf(
          primary.outcome.finalUrl,
          primary.outcome.headers,
          probeOptions,
          hasSensitiveFeatures,
        );
        findings.push(...corsWafResult.findings);

        // 6. Verificación de madurez de divulgación responsable security.txt (RFC 9116)
        securityTxtResult = await analyzeSecurityTxt(primary.outcome.finalUrl, probeOptions);
        findings.push(...securityTxtResult.findings);
        // 7. Inspección profunda de especificaciones OpenAPI / Swagger
        openApiResult = await probeAndAnalyzeOpenApi(primary.outcome.finalUrl, probeOptions);
        if (openApiResult) {
          findings.push(...openApiResult.findings);
        }

        // 8. Sondeo activo de fuga de trazas de depuración (Stack Traces) y rutas internas
        debugLeakResult = await probeAndAnalyzeDebugLeaks(primary.outcome.finalUrl, probeOptions);
        if (debugLeakResult) {
          findings.push(...debugLeakResult.findings);
        }
      } catch {
        // Si ctx.signal fue cancelado o falla la sonda profunda secundaria, se conservan los hallazgos base
      }
    }

    // Deduplicar tecnologías por nombre conservando la de mayor confianza
    const uniqueTechMap = new Map<string, DetectedTechnology>();
    for (const tech of allTechnologies) {
      const existing = uniqueTechMap.get(tech.name);
      if (!existing || (tech.version && !existing.version) || (tech.confidence > existing.confidence)) {
        uniqueTechMap.set(tech.name, tech);
      }
    }
    const technologies = Array.from(uniqueTechMap.values()).sort((a, b) => b.confidence - a.confidence);

    // Deduplicar hallazgos por (ruleId, location) para evitar inflación por redirecciones o sondas redundantes
    const uniqueFindingsMap = new Map<string, FindingDraft>();
    for (const f of findings) {
      const key = `${f.ruleId}::${f.location}`;
      if (!uniqueFindingsMap.has(key)) {
        uniqueFindingsMap.set(key, f);
      }
    }
    const deduplicatedFindings = Array.from(uniqueFindingsMap.values());

    return {
      parameters: { targets: targets.map((t) => t.url), timeoutMs, userAgentPinnedAddress: requireTarget(ctx).address },
      rawResult: {
        probes: audited,
        deepInspection: {
          pagesCrawled: crawlResult?.pages.length ?? 0,
          robotsTxt: crawlResult?.robotsTxt ?? null,
          sitemapFound: crawlResult?.sitemapFound ?? false,
          externalScripts: magecartResult?.totalExternalScripts ?? 0,
          scriptsMissingSri: magecartResult?.scriptsMissingSri ?? [],
          mixedContent: magecartResult?.mixedContentUrls ?? [],
          scriptsInspected: jsSecretsResult?.scriptsAnalyzed ?? 0,
          sourceMapsExposed: jsSecretsResult?.sourceMapsExposed ?? [],
          secretsFoundCount: jsSecretsResult?.secretsFoundCount ?? 0,
          cms: cmsResult
            ? {
                wpUserEnumerationExposed: cmsResult.wpUserEnumerationExposed,
                wpXmlRpcEnabled: cmsResult.wpXmlRpcEnabled,
                wpDebugLogExposed: cmsResult.wpDebugLogExposed,
                graphqlIntrospectionActive: cmsResult.graphqlIntrospectionActive,
              }
            : null,
          corsWaf: corsWafResult
            ? {
                corsOriginReflected: corsWafResult.corsOriginReflected,
                dangerousMethodsAllowed: corsWafResult.dangerousMethodsAllowed,
                wafDetected: corsWafResult.wafDetected,
                wafProvider: corsWafResult.wafProvider ?? null,
              }
            : null,
          securityTxt: securityTxtResult
            ? {
                checked: securityTxtResult.checked,
                status: securityTxtResult.status,
                directives: securityTxtResult.directives ?? null,
              }
            : null,
          openApi: openApiResult
            ? {
                analyzed: openApiResult.analyzed,
                specType: openApiResult.specType,
                totalOperations: openApiResult.totalOperations,
                unauthenticatedOperations: openApiResult.unauthenticatedOperations.length,
                querySecretsCount: openApiResult.querySecretParams.length,
                internalHosts: openApiResult.internalHosts,
              }
            : null,
          debugLeak: debugLeakResult
            ? {
                analyzed: debugLeakResult.analyzed,
                stackTraceDetected: debugLeakResult.stackTraceDetected,
                framework: debugLeakResult.framework ?? null,
                disclosedPathsCount: debugLeakResult.internalPathsDisclosed.length,
                debugHeaders: debugLeakResult.debugHeadersFound,
              }
            : null,
        },
      },
      findings: deduplicatedFindings,
      summary: {
        targetsChecked: targets.length,
        targetsReachable: reachable.length,
        httpsAvailable,
        findingsCount: deduplicatedFindings.length,
        technologies,
        urls: audited.map((a) => ({ url: a.url, reachable: a.reachable, finalUrl: a.finalUrl ?? null, status: a.status ?? null })),
        pagesCrawled: crawlResult?.pages.length ?? 0,
        waf: corsWafResult?.wafProvider ?? (corsWafResult?.wafDetected ? 'WAF Genérico' : 'Ninguno detectado'),
      },
    };
  }
}
