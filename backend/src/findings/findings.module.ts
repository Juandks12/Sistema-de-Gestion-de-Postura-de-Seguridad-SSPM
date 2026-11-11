import { Module } from '@nestjs/common';
import { AiModule } from '../ai/ai.module';
import { RiskModule } from '../risk/risk.module';
import { AttackPathsService } from './attack-paths.service';
import { FindingTriageService } from './finding-triage.service';
import { FindingsController } from './findings.controller';
import { FindingsService } from './findings.service';

@Module({
  imports: [RiskModule, AiModule],
  controllers: [FindingsController],
  providers: [FindingsService, FindingTriageService, AttackPathsService],
  exports: [FindingsService, FindingTriageService, AttackPathsService],
})
export class FindingsModule {}

