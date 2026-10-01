import { Module } from '@nestjs/common';
import { CveLookupService } from './cve-lookup.service';
import { CVE_SOURCE, NvdClient } from './nvd.client';

@Module({
  providers: [CveLookupService, NvdClient, { provide: CVE_SOURCE, useExisting: NvdClient }],
  exports: [CveLookupService],
})
export class VulnerabilitiesModule {}
