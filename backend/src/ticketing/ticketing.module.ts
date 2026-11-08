import { Module } from '@nestjs/common';
import { CryptoVaultModule } from '../common/crypto/crypto-vault.module';
import { PrismaModule } from '../prisma/prisma.module';
import { AzureBoardsConnectorService } from './azure-boards-connector.service';
import { JiraConnectorService } from './jira-connector.service';
import { TicketingController } from './ticketing.controller';
import { TicketingService } from './ticketing.service';

@Module({
  imports: [PrismaModule, CryptoVaultModule],
  controllers: [TicketingController],
  providers: [
    TicketingService,
    JiraConnectorService,
    AzureBoardsConnectorService,
  ],
  exports: [TicketingService],
})
export class TicketingModule {}
