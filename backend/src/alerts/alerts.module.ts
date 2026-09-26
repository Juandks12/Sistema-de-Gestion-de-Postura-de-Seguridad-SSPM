import { Module } from '@nestjs/common';
import { AlertNotifierService } from './alert-notifier.service';
import { AlertsController } from './alerts.controller';
import { AlertsService } from './alerts.service';

@Module({
  controllers: [AlertsController],
  providers: [AlertsService, AlertNotifierService],
  exports: [AlertsService],
})
export class AlertsModule {}
