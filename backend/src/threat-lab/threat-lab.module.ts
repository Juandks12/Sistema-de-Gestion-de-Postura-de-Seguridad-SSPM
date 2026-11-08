import { Module } from '@nestjs/common';
import { FindingsModule } from '../findings/findings.module';
import { RiskModule } from '../risk/risk.module';
import { ThreatLabController } from './threat-lab.controller';
import { ThreatLabService } from './threat-lab.service';

@Module({
  imports: [FindingsModule, RiskModule],
  controllers: [ThreatLabController],
  providers: [ThreatLabService],
  exports: [ThreatLabService],
})
export class ThreatLabModule {}
