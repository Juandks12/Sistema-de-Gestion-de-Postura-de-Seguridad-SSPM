import { FindingDraft } from '../scanner.interface';
import { httpProbe, HttpProbeOptions } from '../web/http-client';

export interface TakeoverFingerprint {
  service: string;
  cnamePatterns: RegExp[];
  bodyPatterns: RegExp[];
  statusCodes?: number[];
}

export const TAKEOVER_FINGERPRINTS: TakeoverFingerprint[] = [
  {
    service: 'GitHub Pages',
    cnamePatterns: [/\.github\.io$/i],
    bodyPatterns: [/There isn't a GitHub Pages site here/i, /For root URLs \(like http:\/\/example\.com\)/i],
    statusCodes: [404],
  },
  {
    service: 'AWS S3 Bucket',
    cnamePatterns: [/\.s3(?:-website)?(?:[-.][a-z0-9-]+)?\.amazonaws\.com$/i],
    bodyPatterns: [/<Code>NoSuchBucket<\/Code>/i, /The specified bucket does not exist/i],
    statusCodes: [404],
  },
  {
    service: 'Microsoft Azure App Service',
    cnamePatterns: [/\.azurewebsites\.net$/i, /\.trafficmanager\.net$/i, /\.cloudapp\.net$/i],
    bodyPatterns: [/404 Web Site not found/i, /Microsoft Azure App Service - Error 404/i],
    statusCodes: [404],
  },
  {
    service: 'Shopify Store',
    cnamePatterns: [/\.myshopify\.com$/i],
    bodyPatterns: [/Sorry, this shop is currently unavailable/i, /domain that is not currently connected to a Shopify store/i],
    statusCodes: [404],
  },
  {
    service: 'Heroku Application',
    cnamePatterns: [/\.herokuapp\.com$/i, /\.herokudns\.com$/i],
    bodyPatterns: [/No such app/i, /Heroku \| No such app/i, /<title>No such app<\/title>/i],
    statusCodes: [404, 502],
  },
  {
    service: 'Vercel Deployment',
    cnamePatterns: [/cname\.vercel-dns\.com$/i, /\.vercel\.app$/i],
    bodyPatterns: [/404: NOT_FOUND/i, /The deployment could not be found on Vercel/i],
    statusCodes: [404],
  },
  {
    service: 'Fastly CDN',
    cnamePatterns: [/\.fastly\.net$/i],
    bodyPatterns: [/Fastly error: unknown domain/i],
    statusCodes: [404],
  },
];

export interface SubdomainCnameInfo {
  subdomain: string;
  cname: string;
}

/**
 * Inspecciona registros CNAME de subdominios para detectar servicios cloud o SaaS huérfanos
 * vulnerables a Subdomain Takeover (Secuestro de Subdominios).
 */
export async function analyzeSubdomainTakeover(
  cnames: SubdomainCnameInfo[],
  probeOptions: HttpProbeOptions,
): Promise<FindingDraft[]> {
  const findings: FindingDraft[] = [];

  for (const { subdomain, cname } of cnames) {
    if (probeOptions.signal.aborted) break;

    const matchedService = TAKEOVER_FINGERPRINTS.find((fp) =>
      fp.cnamePatterns.some((pattern) => pattern.test(cname)),
    );

    if (!matchedService) continue;

    // Probar si el subdominio responde con la firma de recurso huérfano / no reclamado
    const targets = [`https://${subdomain}`, `http://${subdomain}`];
    let confirmedTakeover = false;

    for (const targetUrl of targets) {
      if (confirmedTakeover) break;

      try {
        const probe = await httpProbe(targetUrl, {
          ...probeOptions,
          maxRedirects: 1,
          maxBodyBytes: 32 * 1024,
        });

        if (probe.ok) {
          const bodyText = probe.body.toString('utf8');
          const statusMatches = matchedService.statusCodes
            ? matchedService.statusCodes.includes(probe.status)
            : true;
          const bodyMatches = matchedService.bodyPatterns.some((pat) => pat.test(bodyText));

          if (statusMatches && bodyMatches) {
            confirmedTakeover = true;

            findings.push({
              ruleId: 'DNS-SUBDOMAIN-TAKEOVER',
              location: `${subdomain} (CNAME -> ${cname})`,
              title: `Riesgo Crítico de Subdomain Takeover detectado en ${subdomain} (${matchedService.service})`,
              evidence: {
                subdomain,
                cname,
                service: matchedService.service,
                verifiedUrl: targetUrl,
                httpStatus: probe.status,
                signatureMatched: true,
                impact:
                  'Un atacante puede reclamar este recurso en el proveedor cloud y tomar control total del subdominio para servir phishing o robar credenciales del comercio.',
              },
            });
          }
        }
      } catch {
        // Ignorar fallo de conexión individual
      }
    }
  }

  return findings;
}
