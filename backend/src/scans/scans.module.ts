import { Module } from '@nestjs/common';
import { AlertsModule } from '../alerts/alerts.module';
import { FindingsModule } from '../findings/findings.module';
import { RiskModule } from '../risk/risk.module';
import { NmapRunner } from './nmap/nmap.runner';
import { ScanCancellationService } from './scan-cancellation.service';
import { ScanWorkerService } from './scan-worker.service';
import { Scanner, SCANNERS } from './scanner.interface';
import { PortScanScanner } from './scanners/port-scan.scanner';
import { SensitivePathsScanner } from './scanners/sensitive-paths.scanner';
import { SslCertScanner } from './scanners/ssl-cert.scanner';
import { WebHeadersScanner } from './scanners/web-headers.scanner';
import { ScansController } from './scans.controller';
import { ScansService } from './scans.service';

@Module({
  imports: [FindingsModule, RiskModule, AlertsModule],
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
    {
      provide: SCANNERS,
      inject: [PortScanScanner, WebHeadersScanner, SslCertScanner, SensitivePathsScanner],
      useFactory: (...scanners: Scanner[]) => scanners,
    },
  ],
  exports: [ScansService],
})
export class ScansModule {}
