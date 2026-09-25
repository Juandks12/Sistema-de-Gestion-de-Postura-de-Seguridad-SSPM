import { Module } from '@nestjs/common';
import { NmapRunner } from './nmap/nmap.runner';
import { ScanWorkerService } from './scan-worker.service';
import { ScansController } from './scans.controller';
import { ScansService } from './scans.service';

@Module({
  controllers: [ScansController],
  providers: [ScansService, ScanWorkerService, NmapRunner],
  exports: [ScansService],
})
export class ScansModule {}
