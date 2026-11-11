import { Module } from '@nestjs/common';
import { PrismaModule } from '../prisma/prisma.module';
import { ApiKeysModule } from '../api-keys/api-keys.module';
import { RiskModule } from '../risk/risk.module';
import { ScansModule } from '../scans/scans.module';
import { ComplianceModule } from '../compliance/compliance.module';
import { AiModule } from '../ai/ai.module';
import { McpServerService } from './mcp-server.service';
import { McpController } from './mcp.controller';

@Module({
  imports: [
    PrismaModule,
    ApiKeysModule,
    RiskModule,
    ScansModule,
    ComplianceModule,
    AiModule,
  ],
  controllers: [McpController],
  providers: [McpServerService],
  exports: [McpServerService],
})
export class McpModule {}
