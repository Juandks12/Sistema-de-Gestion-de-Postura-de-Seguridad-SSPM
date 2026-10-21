import { Module } from '@nestjs/common';
import { PrismaModule } from '../prisma/prisma.module';
import { RiskModule } from '../risk/risk.module';
import { CloudAccountsController } from './cloud-accounts.controller';
import { CloudAccountsService } from './cloud-accounts.service';
import { CloudScanService } from './cloud-scan.service';
import { AwsConnectorService } from './connectors/aws-connector.service';
import { AzureConnectorService } from './connectors/azure-connector.service';
import { AwsCspmEvaluatorService } from './evaluators/aws-cspm.evaluator';
import { AzureCspmEvaluatorService } from './evaluators/azure-cspm.evaluator';

@Module({
  imports: [PrismaModule, RiskModule],
  controllers: [CloudAccountsController],
  providers: [
    CloudAccountsService,
    CloudScanService,
    AwsConnectorService,
    AzureConnectorService,
    AwsCspmEvaluatorService,
    AzureCspmEvaluatorService,
  ],
  exports: [
    CloudAccountsService,
    CloudScanService,
    AwsConnectorService,
    AzureConnectorService,
    AwsCspmEvaluatorService,
    AzureCspmEvaluatorService,
  ],
})
export class CloudModule {}
