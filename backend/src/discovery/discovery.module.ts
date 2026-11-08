import { forwardRef, Module } from '@nestjs/common';
import { AssetsModule } from '../assets/assets.module';
import { ScansModule } from '../scans/scans.module';
import { DiscoveryController } from './discovery.controller';
import { DiscoveryService } from './discovery.service';

@Module({
  imports: [AssetsModule, forwardRef(() => ScansModule)],
  controllers: [DiscoveryController],
  providers: [DiscoveryService],
  exports: [DiscoveryService],
})
export class DiscoveryModule {}
