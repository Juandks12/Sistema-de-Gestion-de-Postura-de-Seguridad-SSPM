import { Inject, Injectable, Optional } from '@nestjs/common';
import { AssetType, ScanType } from '@prisma/client';
import { DNS_CLIENT, DnsClient, DnsLookupError } from '../../common/dns/dns-client';
import { analyzeEmailSecurity } from '../email/email-security.analyzer';
import { analyzeDnsSecurity } from '../dns/dns-security.analyzer';
import { DOH_QUERY, DohQueryFn } from '../dns/dnssec';
import { COMMON_DKIM_SELECTORS } from '../email/dkim';
import { ScanExecutionError } from '../scan.errors';
import { ScanContext, Scanner, ScanOutcome } from '../scanner.interface';

/** Seguridad del perímetro DNS y correo del dominio: SPF, DMARC, DKIM, MTA-STS, TLS-RPT, CAA y DNSSEC. */
@Injectable()
export class EmailSecurityScanner implements Scanner {
  readonly type = ScanType.EMAIL_SECURITY;
  readonly assetTypes = [AssetType.DOMAIN] as const;
  readonly passive = true;

  constructor(
    @Inject(DNS_CLIENT) private readonly dns: DnsClient,
    @Optional() @Inject(DOH_QUERY) private readonly dohQuery?: DohQueryFn,
  ) {}

  async run(ctx: ScanContext): Promise<ScanOutcome> {
    try {
      const emailResult = await analyzeEmailSecurity(ctx.asset.value, this.dns, undefined, ctx.signal);
      const dnsResult = await analyzeDnsSecurity(ctx.asset.value, this.dns, this.dohQuery, ctx.signal);

      const summary = {
        ...emailResult.summary,
        caa: dnsResult.summary.caa,
        dnssec: dnsResult.summary.dnssec,
      };

      return {
        parameters: { dkimSelectors: COMMON_DKIM_SELECTORS.length },
        rawResult: summary,
        findings: [...emailResult.findings, ...dnsResult.findings],
        summary,
      };
    } catch (err) {
      if (err instanceof DnsLookupError) throw new ScanExecutionError(err.message);
      throw err;
    }
  }
}
