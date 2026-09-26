import { Module } from '@nestjs/common';
import { RiskModule } from '../risk/risk.module';
import { AssetsController } from './assets.controller';
import { AssetsService } from './assets.service';
import { AssetVerificationService, defaultTxtResolver, TXT_RESOLVER } from './verification/asset-verification.service';

@Module({
  imports: [RiskModule],
  controllers: [AssetsController],
  providers: [AssetsService, AssetVerificationService, { provide: TXT_RESOLVER, useValue: defaultTxtResolver }],
  exports: [AssetsService],
})
export class AssetsModule {}
