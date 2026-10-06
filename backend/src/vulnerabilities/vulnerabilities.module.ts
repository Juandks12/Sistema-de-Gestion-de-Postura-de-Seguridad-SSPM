import { Module } from '@nestjs/common';
import { CveLookupService } from './cve-lookup.service';
import { EPSS_SOURCE, EpssClient } from './epss.client';
import { KEV_SOURCE, KevClient } from './kev.client';
import { KevSyncService } from './kev-sync.service';
import { CVE_SOURCE, NvdClient } from './nvd.client';

@Module({
  providers: [
    CveLookupService,
    NvdClient,
    { provide: CVE_SOURCE, useExisting: NvdClient },
    EpssClient,
    { provide: EPSS_SOURCE, useExisting: EpssClient },
    KevClient,
    { provide: KEV_SOURCE, useExisting: KevClient },
    KevSyncService,
  ],
  exports: [CveLookupService, EpssClient, KevSyncService],
})
export class VulnerabilitiesModule {}
