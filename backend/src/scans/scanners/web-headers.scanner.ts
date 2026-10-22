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
      const drafts = analyzeHeaders({
        finalUrl: outcome.finalUrl,
        status: outcome.status,
        headers: outcome.headers,
        httpsAvailable,
      });
      const techResult = fingerprintTechnologies({
        finalUrl: outcome.finalUrl,
        status: outcome.status,
        headers: outcome.headers,
        bodyText: outcome.body.toString('utf8'),
      });

      findings.push(...drafts, ...techResult.findings);
      allTechnologies.push(...techResult.technologies);

      audited.push({
        url: target.url,
        reachable: true,
        finalUrl: outcome.finalUrl,
        status: outcome.status,
        redirects: outcome.hops.length - 1,
        findings: drafts.length + techResult.findings.length,
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
        },
      },
      findings,
      summary: {
        targetsChecked: targets.length,
        targetsReachable: reachable.length,
        httpsAvailable,
        findingsCount: findings.length,
        technologies,
        urls: audited.map((a) => ({ url: a.url, reachable: a.reachable, finalUrl: a.finalUrl ?? null, status: a.status ?? null })),
        pagesCrawled: crawlResult?.pages.length ?? 0,
        waf: corsWafResult?.wafProvider ?? (corsWafResult?.wafDetected ? 'WAF Genérico' : 'Ninguno detectado'),
      },
    };
  }
}
