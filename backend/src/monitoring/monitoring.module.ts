import { Module } from '@nestjs/common';
import { AlertsModule } from '../alerts/alerts.module';
import { RetentionModule } from '../retention/retention.module';
import { ScansModule } from '../scans/scans.module';
import { MonitoringController } from './monitoring.controller';
import { MonitoringScheduler } from './monitoring.scheduler';
import { MonitoringService } from './monitoring.service';

@Module({
  imports: [ScansModule, AlertsModule, RetentionModule],
  controllers: [MonitoringController],
  providers: [MonitoringScheduler, MonitoringService],
})
export class MonitoringModule {}
