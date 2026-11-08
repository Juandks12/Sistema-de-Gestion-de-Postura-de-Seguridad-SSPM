import { Inject, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AssetType, ScanType } from '@prisma/client';
import { DNS_CLIENT, DnsClient } from '../../common/dns/dns-client';
import { isPrivateOrReservedIp } from '../../common/utils/network.util';
import { CT_SOURCE, CtSource, CtSourceError } from '../../discovery/ct-log.client';
import { subdomainsFromCt } from '../../discovery/hostnames';
import { analyzeSubdomainTakeover, SubdomainCnameInfo } from '../dns/subdomain-takeover.analyzer';
import { ScanExecutionError } from '../scan.errors';
import { abortReason, DiscoveredHostDraft, FindingDraft, ScanContext, Scanner, ScanOutcome } from '../scanner.interface';

const RESOLVE_CONCURRENCY = 10;

/**
 * Descubrimiento pasivo de subdominios (shadow IT) en Certificate
 * Transparency. No se conecta a ningún sistema del cliente: consulta los
 * registros públicos de certificados y resuelve los nombres en DNS.
 */
@Injectable()
export class SubdomainDiscoveryScanner implements Scanner {
  readonly type = ScanType.SUBDOMAIN_DISCOVERY;
  readonly assetTypes = [AssetType.DOMAIN] as const;
  readonly passive = true;

  constructor(
    private readonly config: ConfigService,
    @Inject(CT_SOURCE) private readonly ct: CtSource,
    @Inject(DNS_CLIENT) private readonly dns: DnsClient,
  ) {}

  async run(ctx: ScanContext): Promise<ScanOutcome> {
    const domain = ctx.asset.value;
    const max = this.config.get<number>('SUBDOMAIN_DISCOVERY_MAX_HOSTS') ?? 500;

    let result: Awaited<ReturnType<CtSource['names']>>;
    try {
      result = await this.ct.names(domain, ctx.signal);
    } catch (err) {
      if (abortReason(ctx.signal)) throw new ScanExecutionError('Escaneo interrumpido');
      throw new ScanExecutionError(err instanceof CtSourceError ? err.message : 'No se pudo consultar Certificate Transparency');
    }

    const { hosts, truncated } = subdomainsFromCt(result.names, domain, max);
    const discovered: DiscoveredHostDraft[] = new Array(hosts.length);
    const candidateCnames: SubdomainCnameInfo[] = [];
    let next = 0;
    const worker = async () => {
      while (next < hosts.length) {
        if (abortReason(ctx.signal)) throw new ScanExecutionError('Escaneo interrumpido');
        const i = next++;
        const host = hosts[i];
        // Un fallo de DNS en un nombre no invalida el descubrimiento: se registra como "no resuelve".
        const [addresses, cnames] = await Promise.all([
          this.dns.addresses(host.hostname).catch(() => [] as string[]),
          this.dns.cname(host.hostname).catch(() => [] as string[]),
        ]);
        discovered[i] = { ...host, resolves: addresses.length > 0, addresses: addresses.slice(0, 10) };
        if (cnames.length > 0) {
          candidateCnames.push({ subdomain: host.hostname, cname: cnames[0] });
        }
      }
    };
    await Promise.all(Array.from({ length: Math.min(RESOLVE_CONCURRENCY, hosts.length) }, worker));

    // Evaluar riesgos de Subdomain Takeover sobre los CNAMEs recolectados
    const takeoverFindings = await analyzeSubdomainTakeover(candidateCnames.slice(0, 50), {
      allowPrivate: ctx.allowPrivate,
      signal: ctx.signal,
      timeoutMs: 6000,
    });

    const findings: FindingDraft[] = [...takeoverFindings];

    // Detectar subdominios que exponen direccionamiento IP interno/privado (RFC 1918) en DNS público
    if (!ctx.allowPrivate) {
      const internalLeaks = discovered
        .filter((h) => h && h.resolves)
        .map((h) => ({
          hostname: h.hostname,
          privateAddresses: h.addresses.filter((addr) => isPrivateOrReservedIp(addr)),
        }))
        .filter((item) => item.privateAddresses.length > 0);

      if (internalLeaks.length > 0) {
        findings.push({
          ruleId: 'DNS-INTERNAL-IP-LEAK',
          location: domain,
          title: `Subdominios en DNS público resuelven a direcciones IP privadas/internas (${internalLeaks.length} detectados)`,
          evidence: {
            domain,
            count: internalLeaks.length,
            subdomains: internalLeaks.slice(0, 25),
          },
        });
      }
    }

    return {
      parameters: { source: result.source, maxHosts: max },
      rawResult: { source: result.source, certificateNames: result.names.length, candidateCnamesCount: candidateCnames.length },
      findings,
      discoveredHosts: discovered,
      summary: {
        source: result.source,
        subdomains: discovered.length,
        resolving: discovered.filter((h) => h.resolves).length,
        takeoverFindingsCount: takeoverFindings.length,
        truncated,
      },
    };
  }
}
