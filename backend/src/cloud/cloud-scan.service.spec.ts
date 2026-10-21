import {
  CloudAccountStatus,
  CloudAuthType,
  CloudProvider,
  CloudResourceType,
  FindingSeverity,
  FindingStatus,
} from '@prisma/client';
import { PrismaService } from '../prisma/prisma.service';
import { RiskScoresService } from '../risk/risk-scores.service';
import { CloudAccountsService } from './cloud-accounts.service';
import {
  CloudScanService,
  computeDefaultCspmDueDate,
} from './cloud-scan.service';
import { AwsCspmEvaluatorService } from './evaluators/aws-cspm.evaluator';
import { AzureCspmEvaluatorService } from './evaluators/azure-cspm.evaluator';

describe('CloudScanService', () => {
  let service: CloudScanService;
  let prismaMock: {
    asset: { upsert: jest.Mock; update: jest.Mock };
    cloudAccount: { update: jest.Mock; findMany: jest.Mock };
    cloudResource: { upsert: jest.Mock; deleteMany: jest.Mock; findMany: jest.Mock };
    finding: {
      findUnique: jest.Mock;
      create: jest.Mock;
      update: jest.Mock;
      updateMany: jest.Mock;
      findMany: jest.Mock;
    };
    $transaction: jest.Mock;
  };
  let cloudAccountsMock: {
    getDecryptedCredentials: jest.Mock;
    sanitizeAccount: jest.Mock;
  };
  let awsEvaluatorMock: { evaluateAccount: jest.Mock };
  let azureEvaluatorMock: { evaluateSubscription: jest.Mock };
  let riskScoresMock: { snapshot: jest.Mock };

  beforeEach(() => {
    prismaMock = {
      asset: {
        upsert: jest.fn(),
        update: jest.fn().mockResolvedValue({}),
      },
      cloudAccount: {
        update: jest.fn().mockImplementation(({ data }) => ({
          id: 'acc-1',
          organizationId: 'org-1',
          provider: CloudProvider.AWS,
          name: 'AWS Prod',
          authType: CloudAuthType.ROLE_ARN,
          accountOrSubscriptionId: '123456789012',
          ...data,
        })),
        findMany: jest.fn(),
      },
      cloudResource: {
        upsert: jest.fn().mockResolvedValue({ id: 'res-1' }),
        deleteMany: jest.fn().mockResolvedValue({ count: 0 }),
        findMany: jest.fn(),
      },
      finding: {
        findUnique: jest.fn(),
        create: jest.fn().mockResolvedValue({ id: 'f-new' }),
        update: jest.fn().mockResolvedValue({ id: 'f-existing' }),
        updateMany: jest.fn().mockResolvedValue({ count: 2 }),
        findMany: jest.fn(),
      },
      $transaction: jest.fn().mockImplementation(async (cb) => cb(prismaMock)),
    };

    cloudAccountsMock = {
      getDecryptedCredentials: jest.fn().mockResolvedValue({
        account: {
          id: 'acc-1',
          organizationId: 'org-1',
          provider: CloudProvider.AWS,
          name: 'AWS Prod',
          authType: CloudAuthType.ROLE_ARN,
          status: CloudAccountStatus.CONNECTED,
          accountOrSubscriptionId: '123456789012',
          awsRoleArn: 'arn:aws:iam::123456789012:role/Auditor',
          awsExternalId: 'sspm-org-123',
          monitoredRegions: ['us-east-1'],
          assetId: 'asset-1',
        },
        credentials: {},
      }),
      sanitizeAccount: jest.fn().mockImplementation((acc) => acc),
    };

    awsEvaluatorMock = {
      evaluateAccount: jest.fn().mockResolvedValue({
        provider: CloudProvider.AWS,
        accountOrSubscriptionId: '123456789012',
        simulated: true,
        evaluatedRulesCount: 19,
        warnings: [],
        resources: [
          {
            nativeId: 'arn:aws:s3:::public-bucket',
            name: 'public-bucket',
            resourceType: CloudResourceType.AWS_S3_BUCKET,
            region: 'us-east-1',
            configuration: { publicAccessBlocked: false },
          },
        ],
        findings: [
          {
            ruleId: 'AWS-S3-PUBLIC-READ',
            nativeId: 'arn:aws:s3:::public-bucket',
            resourceName: 'public-bucket',
            resourceType: CloudResourceType.AWS_S3_BUCKET,
            region: 'us-east-1',
            evidence: { bucketName: 'public-bucket' },
          },
          {
            ruleId: 'AWS-S3-UNENCRYPTED',
            nativeId: 'arn:aws:s3:::public-bucket',
            resourceName: 'public-bucket',
            resourceType: CloudResourceType.AWS_S3_BUCKET,
            region: 'us-east-1',
            evidence: { bucketName: 'public-bucket' },
          },
        ],
      }),
    };

    azureEvaluatorMock = {
      evaluateSubscription: jest.fn(),
    };

    riskScoresMock = {
      snapshot: jest.fn().mockResolvedValue({
        asset: { score: 62, grade: 'C' },
        organization: { score: 75, grade: 'B' },
      }),
    };

    service = new CloudScanService(
      prismaMock as unknown as PrismaService,
      cloudAccountsMock as unknown as CloudAccountsService,
      awsEvaluatorMock as unknown as AwsCspmEvaluatorService,
      azureEvaluatorMock as unknown as AzureCspmEvaluatorService,
      riskScoresMock as unknown as RiskScoresService,
    );
  });

  describe('computeDefaultCspmDueDate', () => {
    it('asigna SLA de 24h a CRITICAL, 7d a HIGH, 30d a MEDIUM y 90d a LOW', () => {
      const base = new Date('2026-10-20T00:00:00.000Z');

      const crit = computeDefaultCspmDueDate(FindingSeverity.CRITICAL, base);
      expect(crit.getTime() - base.getTime()).toBe(24 * 60 * 60 * 1000);

      const high = computeDefaultCspmDueDate(FindingSeverity.HIGH, base);
      expect(high.getTime() - base.getTime()).toBe(7 * 24 * 60 * 60 * 1000);

      const med = computeDefaultCspmDueDate(FindingSeverity.MEDIUM, base);
      expect(med.getTime() - base.getTime()).toBe(30 * 24 * 60 * 60 * 1000);

      const low = computeDefaultCspmDueDate(FindingSeverity.LOW, base);
      expect(low.getTime() - base.getTime()).toBe(90 * 24 * 60 * 60 * 1000);
    });
  });

  describe('runAccountAudit', () => {
    it('sincroniza recursos, crea/reabre hallazgos, auto-resuelve corregidos y calcula el Security Score', async () => {
      // Primer hallazgo no existe -> se crea; segundo estaba RESOLVED -> se reabre
      prismaMock.finding.findUnique
        .mockResolvedValueOnce(null)
        .mockResolvedValueOnce({
          id: 'f-resolved',
          status: FindingStatus.RESOLVED,
          dueDate: null,
        });

      const response = await service.runAccountAudit('org-1', 'acc-1', {
        simulate: true,
        actorId: 'user-1',
      });

      expect(response.simulated).toBe(true);
      expect(response.evaluatedRulesCount).toBe(19);
      expect(response.stats.resourcesDiscovered).toBe(1);
      expect(response.stats.findingsCreated).toBe(1);
      expect(response.stats.findingsReopened).toBe(1);
      expect(response.stats.findingsResolved).toBe(2);
      expect(response.stats.activeFindings).toBe(2);
      expect(response.stats.bySeverity.CRITICAL).toBe(1);
      expect(response.stats.bySeverity.HIGH).toBe(1);
      expect(response.stats.score).toBe(62);
      expect(response.stats.grade).toBe('C');

      expect(prismaMock.cloudResource.upsert).toHaveBeenCalledTimes(1);
      expect(prismaMock.finding.create).toHaveBeenCalledTimes(1);
      expect(prismaMock.finding.update).toHaveBeenCalledTimes(1);
      expect(prismaMock.finding.updateMany).toHaveBeenCalledTimes(1);
      expect(riskScoresMock.snapshot).toHaveBeenCalledTimes(1);
    });
  });

  describe('getCloudPostureSummary', () => {
    it('consolida métricas de cuentas, inventario y hallazgos por proveedor y severidad', async () => {
      prismaMock.cloudAccount.findMany.mockResolvedValueOnce([
        {
          id: 'acc-1',
          provider: CloudProvider.AWS,
          status: CloudAccountStatus.CONNECTED,
          resourceCount: 5,
          failingFindingCount: 2,
          lastAuditedAt: new Date(),
        },
        {
          id: 'acc-2',
          provider: CloudProvider.AZURE,
          status: CloudAccountStatus.CONNECTED,
          resourceCount: 3,
          failingFindingCount: 1,
          lastAuditedAt: new Date(),
        },
      ]);

      prismaMock.cloudResource.findMany.mockResolvedValueOnce([
        {
          provider: CloudProvider.AWS,
          resourceType: CloudResourceType.AWS_S3_BUCKET,
          hasActiveFindings: true,
        },
        {
          provider: CloudProvider.AZURE,
          resourceType: CloudResourceType.AZURE_STORAGE_ACCOUNT,
          hasActiveFindings: false,
        },
      ]);

      prismaMock.finding.findMany.mockResolvedValueOnce([
        {
          severity: FindingSeverity.CRITICAL,
          category: 'CLOUD_STORAGE',
        },
      ]);

      const summary = await service.getCloudPostureSummary('org-1');

      expect(summary.accounts.total).toBe(2);
      expect(summary.accounts.connected).toBe(2);
      expect(summary.accounts.byProvider).toEqual({ AWS: 1, AZURE: 1 });
      expect(summary.resources.total).toBe(2);
      expect(summary.resources.withFindings).toBe(1);
      expect(summary.resources.clean).toBe(1);
      expect(summary.findings.totalOpen).toBe(1);
      expect(summary.findings.bySeverity.CRITICAL).toBe(1);
    });
  });
});
