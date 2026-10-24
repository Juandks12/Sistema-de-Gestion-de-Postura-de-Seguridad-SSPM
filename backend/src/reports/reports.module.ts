import { Module } from '@nestjs/common';
import { FindingsModule } from '../findings/findings.module';
import { RiskModule } from '../risk/risk.module';
import { ExecutiveSummaryService } from './executive-summary.service';
import { ReportsController } from './reports.controller';
import { ReportsService } from './reports.service';

@Module({
  imports: [RiskModule, FindingsModule],
  controllers: [ReportsController],
  providers: [ReportsService, ExecutiveSummaryService],
  exports: [ReportsService, ExecutiveSummaryService],
})
export class ReportsModule {}
