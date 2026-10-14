import { Module } from '@nestjs/common';
import { RiskModule } from '../risk/risk.module';
import { FindingTriageService } from './finding-triage.service';
import { FindingsController } from './findings.controller';
import { FindingsService } from './findings.service';

@Module({
  imports: [RiskModule],
  controllers: [FindingsController],
  providers: [FindingsService, FindingTriageService],
  exports: [FindingsService, FindingTriageService],
})
export class FindingsModule {}
