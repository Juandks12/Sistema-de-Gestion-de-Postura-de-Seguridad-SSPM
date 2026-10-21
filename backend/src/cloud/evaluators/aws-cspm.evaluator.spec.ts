import { CloudAuthType, CloudProvider, CloudResourceType } from '@prisma/client';
import { AwsConnectorService } from '../connectors/aws-connector.service';
import { AwsCspmEvaluatorService } from './aws-cspm.evaluator';
import { DiscoveredCloudResource } from './cspm-evaluator.types';

describe('AwsCspmEvaluatorService', () => {
  let evaluator: AwsCspmEvaluatorService;
  let awsConnectorMock: {
    resolveCredentials: jest.Mock;
    executeSignedXmlRequest: jest.Mock;
  };

  beforeEach(() => {
    awsConnectorMock = {
      resolveCredentials: jest.fn(),
      executeSignedXmlRequest: jest.fn(),
    };
    evaluator = new AwsCspmEvaluatorService(
      awsConnectorMock as unknown as AwsConnectorService,
    );
  });

  it('evalúa las 19 reglas CSPM de AWS cuando los recursos presentan malas configuraciones', () => {
    const accountId = '123456789012';
    const region = 'us-east-1';

    const resources: DiscoveredCloudResource[] = [
      ...evaluator.buildBenchmarkInventory(accountId, region),
      {
        nativeId: `arn:aws:ec2:${region}:${accountId}:security-group/sg-rdp-all`,
        name: 'sg-rdp-all',
        resourceType: CloudResourceType.AWS_SECURITY_GROUP,
        region,
        configuration: {
          groupId: 'sg-rdp-all',
          allowsSshFromInternet: false,
          allowsRdpFromInternet: true,
          allowsAllTrafficFromInternet: true,
        },
      },
    ];

    const findings = evaluator.evaluateInventoryRules(accountId, resources);
    const detectedRuleIds = new Set(findings.map((f) => f.ruleId));

    expect(detectedRuleIds).toEqual(
      new Set([
        'AWS-IAM-ROOT-MFA',
        'AWS-IAM-USER-NO-MFA',
        'AWS-IAM-KEY-ROTATION',
        'AWS-IAM-ADMIN-POLICY',
        'AWS-S3-PUBLIC-READ',
        'AWS-S3-UNENCRYPTED',
        'AWS-S3-LOGGING-OFF',
        'AWS-SG-SSH-OPEN',
        'AWS-SG-RDP-OPEN',
        'AWS-SG-ALL-TRAFFIC',
        'AWS-VPC-FLOW-LOGS',
        'AWS-EC2-IMDSV1-ENABLED',
        'AWS-EBS-UNENCRYPTED',
        'AWS-EC2-PUBLIC-IP',
        'AWS-RDS-PUBLIC-ACCESS',
        'AWS-RDS-UNENCRYPTED',
        'AWS-RDS-NO-BACKUP',
        'AWS-TRAIL-DISABLED',
        'AWS-GUARDDUTY-OFF',
      ]),
    );
  });

  it('no genera hallazgos cuando todos los recursos AWS cumplen las líneas base de seguridad', () => {
    const accountId = '123456789012';
    const compliantResources: DiscoveredCloudResource[] = [
      {
        nativeId: `arn:aws:iam::${accountId}:root`,
        name: 'root',
        resourceType: CloudResourceType.AWS_IAM_USER,
        region: 'global',
        configuration: { isRootAccount: true, accountMfaEnabled: true },
      },
      {
        nativeId: `arn:aws:iam::${accountId}:user/alice`,
        name: 'alice',
        resourceType: CloudResourceType.AWS_IAM_USER,
        region: 'global',
        configuration: {
          isRootAccount: false,
          hasConsolePassword: true,
          mfaEnabled: true,
          oldestActiveKeyAgeDays: 15,
          hasAdminPolicy: false,
        },
      },
      {
        nativeId: 'arn:aws:s3:::secure-bucket',
        name: 'secure-bucket',
        resourceType: CloudResourceType.AWS_S3_BUCKET,
        region: 'us-east-1',
        configuration: {
          publicAccessBlocked: true,
          defaultEncryptionEnabled: true,
          accessLoggingEnabled: true,
        },
      },
      {
        nativeId: `arn:aws:ec2:us-east-1:${accountId}:security-group/sg-secure`,
        name: 'sg-secure',
        resourceType: CloudResourceType.AWS_SECURITY_GROUP,
        region: 'us-east-1',
        configuration: {
          allowsSshFromInternet: false,
          allowsRdpFromInternet: false,
          allowsAllTrafficFromInternet: false,
        },
      },
      {
        nativeId: `arn:aws:ec2:us-east-1:${accountId}:vpc/vpc-secure`,
        name: 'vpc-secure',
        resourceType: CloudResourceType.AWS_VPC,
        region: 'us-east-1',
        configuration: { flowLogsEnabled: true },
      },
      {
        nativeId: `arn:aws:ec2:us-east-1:${accountId}:instance/i-secure`,
        name: 'i-secure',
        resourceType: CloudResourceType.AWS_EC2_INSTANCE,
        region: 'us-east-1',
        configuration: {
          imdsv1Enabled: false,
          hasUnencryptedVolume: false,
          hasPublicIp: false,
        },
      },
      {
        nativeId: `arn:aws:rds:us-east-1:${accountId}:db:rds-secure`,
        name: 'rds-secure',
        resourceType: CloudResourceType.AWS_RDS_INSTANCE,
        region: 'us-east-1',
        configuration: {
          publiclyAccessible: false,
          storageEncrypted: true,
          backupRetentionPeriod: 14,
        },
      },
      {
        nativeId: `arn:aws:cloudtrail:us-east-1:${accountId}:trail/main`,
        name: 'main',
        resourceType: CloudResourceType.AWS_CLOUDTRAIL,
        region: 'us-east-1',
        configuration: {
          serviceType: 'CLOUDTRAIL',
          isMultiRegionTrail: true,
          logFileValidationEnabled: true,
        },
      },
      {
        nativeId: `arn:aws:guardduty:us-east-1:${accountId}:detector/det-1`,
        name: 'guardduty-us-east-1',
        resourceType: CloudResourceType.AWS_CLOUDTRAIL,
        region: 'us-east-1',
        configuration: {
          serviceType: 'GUARDDUTY',
          detectorEnabled: true,
        },
      },
    ];

    const findings = evaluator.evaluateInventoryRules(accountId, compliantResources);
    expect(findings).toHaveLength(0);
  });

  it('ejecuta evaluateAccount en modo simulación cuando simulate=true', async () => {
    const result = await evaluator.evaluateAccount({
      authInput: {
        authType: CloudAuthType.ROLE_ARN,
        accountId: '123456789012',
        roleArn: 'arn:aws:iam::123456789012:role/Auditor',
      },
      monitoredRegions: ['us-east-1'],
      simulate: true,
    });

    expect(result.provider).toBe(CloudProvider.AWS);
    expect(result.simulated).toBe(true);
    expect(result.evaluatedRulesCount).toBe(19);
    expect(result.resources.length).toBeGreaterThan(0);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(awsConnectorMock.resolveCredentials).not.toHaveBeenCalled();
  });
});
