import { Inject, Injectable } from '@nestjs/common';
import { AssetType, ScanType } from '@prisma/client';
import { DNS_CLIENT, DnsClient, DnsLookupError } from '../../common/dns/dns-client';
import { analyzeEmailSecurity } from '../email/email-security.analyzer';
import { COMMON_DKIM_SELECTORS } from '../email/dkim';
import { ScanExecutionError } from '../scan.errors';
import { ScanContext, Scanner, ScanOutcome } from '../scanner.interface';

/** Seguridad del correo del dominio: SPF, DMARC y DKIM (solo consultas DNS). */
@Injectable()
export class EmailSecurityScanner implements Scanner {
  readonly type = ScanType.EMAIL_SECURITY;
  readonly assetTypes = [AssetType.DOMAIN] as const;
  readonly passive = true;

  constructor(@Inject(DNS_CLIENT) private readonly dns: DnsClient) {}

  async run(ctx: ScanContext): Promise<ScanOutcome> {
    try {
      const { findings, summary } = await analyzeEmailSecurity(ctx.asset.value, this.dns);
      return {
        parameters: { dkimSelectors: COMMON_DKIM_SELECTORS.length },
        rawResult: summary,
        findings,
        summary: { ...summary },
      };
    } catch (err) {
      if (err instanceof DnsLookupError) throw new ScanExecutionError(err.message);
      throw err;
    }
  }
}
