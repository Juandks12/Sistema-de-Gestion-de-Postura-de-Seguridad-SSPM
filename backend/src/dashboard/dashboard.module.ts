import { Module } from '@nestjs/common';
import { RiskModule } from '../risk/risk.module';
import { DashboardController } from './dashboard.controller';
import { DashboardService } from './dashboard.service';

@Module({
  imports: [RiskModule],
  controllers: [DashboardController],
  providers: [DashboardService],
})
export class DashboardModule {}
