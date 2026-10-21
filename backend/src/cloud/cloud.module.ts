import { Module } from '@nestjs/common';
import { PrismaModule } from '../prisma/prisma.module';
import { CloudAccountsController } from './cloud-accounts.controller';
import { CloudAccountsService } from './cloud-accounts.service';
import { AwsConnectorService } from './connectors/aws-connector.service';
import { AzureConnectorService } from './connectors/azure-connector.service';

@Module({
  imports: [PrismaModule],
  controllers: [CloudAccountsController],
  providers: [
    CloudAccountsService,
    AwsConnectorService,
    AzureConnectorService,
  ],
  exports: [
    CloudAccountsService,
    AwsConnectorService,
    AzureConnectorService,
  ],
})
export class CloudModule {}
