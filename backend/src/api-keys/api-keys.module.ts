import { Module } from '@nestjs/common';
import { AuditModule } from '../audit/audit.module';
import { PrismaModule } from '../prisma/prisma.module';
import { ApiKeysController } from './api-keys.controller';
import { ApiKeysService } from './api-keys.service';
import { PublicApiKeyGuard } from './public-api-key.guard';

@Module({
  imports: [PrismaModule, AuditModule],
  controllers: [ApiKeysController],
  providers: [ApiKeysService, PublicApiKeyGuard],
  exports: [ApiKeysService, PublicApiKeyGuard],
})
export class ApiKeysModule {}
