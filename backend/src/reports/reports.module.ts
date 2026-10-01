import { Module } from '@nestjs/common';
import { RiskModule } from '../risk/risk.module';
import { ReportsController } from './reports.controller';
import { ReportsService } from './reports.service';

@Module({
  imports: [RiskModule],
  controllers: [ReportsController],
  providers: [ReportsService],
})
export class ReportsModule {}
