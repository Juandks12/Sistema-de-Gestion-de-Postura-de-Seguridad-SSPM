import { Module } from '@nestjs/common';
import { AiModule } from '../ai/ai.module';
import { FindingsModule } from '../findings/findings.module';
import { RiskModule } from '../risk/risk.module';
import { ThreatLabController } from './threat-lab.controller';
import { ThreatLabService } from './threat-lab.service';

@Module({
  imports: [FindingsModule, RiskModule, AiModule],
  controllers: [ThreatLabController],
  providers: [ThreatLabService],
  exports: [ThreatLabService],
})
export class ThreatLabModule {}

