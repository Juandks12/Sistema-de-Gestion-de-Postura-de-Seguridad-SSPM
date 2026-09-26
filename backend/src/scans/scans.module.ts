import { Module } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { createDnsClient, DNS_CLIENT } from '../common/dns/dns-client';
import { CT_SOURCE, CtLogClient } from '../discovery/ct-log.client';
import { AlertsModule } from '../alerts/alerts.module';
import { FindingsModule } from '../findings/findings.module';
import { DiscoveryModule } from '../discovery/discovery.module';
import { RiskModule } from '../risk/risk.module';
import { VulnerabilitiesModule } from '../vulnerabilities/vulnerabilities.module';
import { NmapRunner } from './nmap/nmap.runner';
import { ScanCancellationService } from './scan-cancellation.service';
import { ScanWorkerService } from './scan-worker.service';
import { ScanType } from '@prisma/client';
import { Scanner, SCANNERS } from './scanner.interface';
import { PortScanScanner } from './scanners/port-scan.scanner';
import { EmailSecurityScanner } from './scanners/email-security.scanner';
import { SensitivePathsScanner } from './scanners/sensitive-paths.scanner';
import { SslCertScanner } from './scanners/ssl-cert.scanner';
import { SubdomainDiscoveryScanner } from './scanners/subdomain-discovery.scanner';
import { WebHeadersScanner } from './scanners/web-headers.scanner';
import { ScansController } from './scans.controller';
import { ScansService } from './scans.service';

@Module({
  imports: [FindingsModule, RiskModule, AlertsModule, VulnerabilitiesModule, DiscoveryModule],
  controllers: [ScansController],
  providers: [
    ScansService,
    ScanWorkerService,
    ScanCancellationService,
    NmapRunner,
    PortScanScanner,
    WebHeadersScanner,
    SslCertScanner,
    SensitivePathsScanner,
    EmailSecurityScanner,
    SubdomainDiscoveryScanner,
    { provide: DNS_CLIENT, useFactory: () => createDnsClient() },
    { provide: CT_SOURCE, useClass: CtLogClient },
    {
      provide: SCANNERS,
      inject: [
        ConfigService,
        PortScanScanner,
        WebHeadersScanner,
        SslCertScanner,
        SensitivePathsScanner,
        EmailSecurityScanner,
        SubdomainDiscoveryScanner,
      ],
      useFactory: (config: ConfigService, ...scanners: Scanner[]) =>
        // El descubrimiento de subdominios consulta servicios externos y se puede desactivar.
        scanners.filter(
          (s) => s.type !== ScanType.SUBDOMAIN_DISCOVERY || config.get<boolean>('SUBDOMAIN_DISCOVERY_ENABLED') !== false,
        ),
    },
  ],
  exports: [ScansService],
})
export class ScansModule {}
