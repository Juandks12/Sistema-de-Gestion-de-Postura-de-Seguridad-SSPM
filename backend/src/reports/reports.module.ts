import { Module } from '@nestjs/common';
import { AiModule } from '../ai/ai.module';
import { ComplianceModule } from '../compliance/compliance.module';
import { FindingsModule } from '../findings/findings.module';
import { RiskModule } from '../risk/risk.module';
import { ExecutiveSummaryService } from './executive-summary.service';
import { ReportsController } from './reports.controller';
import { ReportsService } from './reports.service';

@Module({
  imports: [RiskModule, FindingsModule, ComplianceModule, AiModule],
  controllers: [ReportsController],
  providers: [ReportsService, ExecutiveSummaryService],
  exports: [ReportsService, ExecutiveSummaryService],
})
export class ReportsModule {}

