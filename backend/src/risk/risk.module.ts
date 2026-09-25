import { Module } from '@nestjs/common';
import { RiskScoresController } from './risk-scores.controller';
import { RiskScoresService } from './risk-scores.service';

@Module({
  controllers: [RiskScoresController],
  providers: [RiskScoresService],
  exports: [RiskScoresService],
})
export class RiskModule {}
