import { Module } from '@nestjs/common';
import { ScansModule } from '../scans/scans.module';
import { MonitoringController } from './monitoring.controller';
import { MonitoringScheduler } from './monitoring.scheduler';
import { MonitoringService } from './monitoring.service';

@Module({
  imports: [ScansModule],
  controllers: [MonitoringController],
  providers: [MonitoringScheduler, MonitoringService],
})
export class MonitoringModule {}
