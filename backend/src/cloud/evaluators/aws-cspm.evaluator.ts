import { Injectable, Logger } from '@nestjs/common';
import {
  CloudProvider,
  CloudResourceType,
} from '@prisma/client';
import {
  AwsAuthInput,
  AwsConnectorService,
} from '../connectors/aws-connector.service';
import { AwsCredentials } from '../connectors/aws-sigv4.util';
import { CSPM_RULES } from '../cspm.catalog';
import {
  CloudAuditExecutionResult,
  CspmFindingDraft,
  DiscoveredCloudResource,
} from './cspm-evaluator.types';

function toArray<T>(val: T | T[] | undefined | null): T[] {
  if (val === undefined || val === null) return [];
  return Array.isArray(val) ? val : [val];
}

@Injectable()
export class AwsCspmEvaluatorService {
  private readonly logger = new Logger(AwsCspmEvaluatorService.name);
  private readonly awsRuleCount = CSPM_RULES.filter(
    (r) => r.provider === CloudProvider.AWS,
  ).length;

  constructor(private readonly awsConnector: AwsConnectorService) {}

  /**
   * Ejecuta la auditoría completa de postura CSPM sobre una cuenta de AWS:
   * - Si se indica `simulate = true` o el accountId es `000000000000`, utiliza un inventario
   *   de referencia determinístico para validación/demostración sin llamadas externas.
   * - En caso contrario, resuelve credenciales vía AWS STS/IAM y recolecta el inventario real
   *   en las regiones monitoreadas, evaluando las 19 reglas AWS del catálogo CSPM.
   */
  async evaluateAccount(params: {
    authInput: AwsAuthInput;
    monitoredRegions: string[];
    simulate?: boolean;
  }): Promise<CloudAuditExecutionResult> {
    const accountId = params.authInput.accountId.trim();
    const regions =
      params.monitoredRegions.length > 0
        ? params.monitoredRegions
        : ['us-east-1', 'us-west-2'];

    const isSandbox =
      params.simulate === true || accountId === '000000000000';

    if (isSandbox) {
      const resources = this.buildBenchmarkInventory(accountId, regions[0] ?? 'us-east-1');
      const findings = this.evaluateInventoryRules(accountId, resources);
      return {
        provider: CloudProvider.AWS,
        accountOrSubscriptionId: accountId,
        simulated: true,
        evaluatedRulesCount: this.awsRuleCount,
        resources,
        findings,
        warnings: [],
      };
    }

    const warnings: string[] = [];
    const { credentials } = await this.awsConnector.resolveCredentials(
      params.authInput,
    );

    const resources: DiscoveredCloudResource[] = [];

    // 1. IAM (Global)
    try {
      const iamResources = await this.collectIamResources(accountId, credentials);
      resources.push(...iamResources);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      this.logger.warn(`AWS IAM collection warning (${accountId}): ${msg}`);
      warnings.push(`IAM: ${msg}`);
    }

    // 2. S3 (Global)
    try {
      const s3Resources = await this.collectS3Resources(accountId, credentials);
      resources.push(...s3Resources);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      this.logger.warn(`AWS S3 collection warning (${accountId}): ${msg}`);
      warnings.push(`S3: ${msg}`);
    }

    // 3. Servicios regionales (EC2, VPC, EBS, RDS, CloudTrail, GuardDuty)
    for (const region of regions) {
      try {
        const ec2Resources = await this.collectEc2AndNetworkResources(
          accountId,
          region,
          credentials,
        );
        resources.push(...ec2Resources);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        warnings.push(`EC2 (${region}): ${msg}`);
      }

      try {
        const rdsResources = await this.collectRdsResources(
          accountId,
          region,
          credentials,
        );
        resources.push(...rdsResources);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        warnings.push(`RDS (${region}): ${msg}`);
      }

      try {
        const loggingResources = await this.collectLoggingResources(
          accountId,
          region,
          credentials,
        );
        resources.push(...loggingResources);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        warnings.push(`Logging (${region}): ${msg}`);
      }
    }

    const findings = this.evaluateInventoryRules(accountId, resources);

    return {
      provider: CloudProvider.AWS,
      accountOrSubscriptionId: accountId,
      simulated: false,
      evaluatedRulesCount: this.awsRuleCount,
      resources,
      findings,
      warnings,
    };
  }

  /**
   * Evalúa las 19 reglas CSPM de AWS sobre el inventario recolectado de recursos.
   * Función pura y determinística para permitir pruebas exhaustivas de cada regla.
   */
  evaluateInventoryRules(
    accountId: string,
    resources: DiscoveredCloudResource[],
  ): CspmFindingDraft[] {
    const findings: CspmFindingDraft[] = [];
    const nowMs = Date.now();
    const ninetyDaysMs = 90 * 24 * 60 * 60 * 1000;

    for (const res of resources) {
      const cfg = res.configuration ?? {};

      // ==========================================
      // 1. IAM (Root & Users)
      // ==========================================
      if (res.resourceType === CloudResourceType.AWS_IAM_USER) {
        if (cfg.isRootAccount === true) {
          if (cfg.accountMfaEnabled === false) {
            findings.push({
              ruleId: 'AWS-IAM-ROOT-MFA',
              nativeId: res.nativeId,
              resourceName: res.name,
              resourceType: res.resourceType,
              region: res.region,
              evidence: {
                accountId,
                accountMfaEnabled: false,
              },
            });
          }
          continue;
        }

        // Usuario IAM estándar
        if (cfg.hasConsolePassword === true && cfg.mfaEnabled === false) {
          findings.push({
            ruleId: 'AWS-IAM-USER-NO-MFA',
            nativeId: res.nativeId,
            resourceName: res.name,
            resourceType: res.resourceType,
            region: res.region,
            evidence: {
              userName: res.name,
              hasConsolePassword: true,
              mfaDevicesCount: 0,
            },
          });
        }

        const oldestKeyCreatedAt = cfg.oldestActiveKeyCreatedAt as string | undefined;
        const explicitKeyAgeDays = cfg.oldestActiveKeyAgeDays as number | undefined;
        let keyAgeDays = explicitKeyAgeDays ?? 0;
        if (!explicitKeyAgeDays && oldestKeyCreatedAt) {
          const createdTime = new Date(oldestKeyCreatedAt).getTime();
          if (!Number.isNaN(createdTime)) {
            keyAgeDays = Math.floor((nowMs - createdTime) / (24 * 60 * 60 * 1000));
          }
        }
        if (
          keyAgeDays > 90 ||
          (oldestKeyCreatedAt &&
            nowMs - new Date(oldestKeyCreatedAt).getTime() > ninetyDaysMs)
        ) {
          findings.push({
            ruleId: 'AWS-IAM-KEY-ROTATION',
            nativeId: res.nativeId,
            resourceName: res.name,
            resourceType: res.resourceType,
            region: res.region,
            evidence: {
              userName: res.name,
              accessKeyId: cfg.oldestActiveKeyId ?? 'AKIA****************',
              ageDays: keyAgeDays,
              thresholdDays: 90,
            },
          });
        }

        if (cfg.hasAdminPolicy === true) {
          findings.push({
            ruleId: 'AWS-IAM-ADMIN-POLICY',
            nativeId: res.nativeId,
            resourceName: res.name,
            resourceType: res.resourceType,
            region: res.region,
            evidence: {
              userName: res.name,
              attachedPolicies: cfg.attachedPolicies ?? ['AdministratorAccess'],
            },
          });
        }
      }

      // ==========================================
      // 2. S3 Buckets
      // ==========================================
      if (res.resourceType === CloudResourceType.AWS_S3_BUCKET) {
        if (cfg.publicAccessBlocked === false) {
          findings.push({
            ruleId: 'AWS-S3-PUBLIC-READ',
            nativeId: res.nativeId,
            resourceName: res.name,
            resourceType: res.resourceType,
            region: res.region,
            evidence: {
              bucketName: res.name,
              publicAccessBlock: cfg.publicAccessBlockConfig ?? null,
            },
          });
        }

        if (cfg.defaultEncryptionEnabled === false) {
          findings.push({
            ruleId: 'AWS-S3-UNENCRYPTED',
            nativeId: res.nativeId,
            resourceName: res.name,
            resourceType: res.resourceType,
            region: res.region,
            evidence: {
              bucketName: res.name,
              sseAlgorithm: null,
            },
          });
        }

        if (cfg.accessLoggingEnabled === false) {
          findings.push({
            ruleId: 'AWS-S3-LOGGING-OFF',
            nativeId: res.nativeId,
            resourceName: res.name,
            resourceType: res.resourceType,
            region: res.region,
            evidence: {
              bucketName: res.name,
              targetBucket: null,
            },
          });
        }
      }

      // ==========================================
      // 3. Security Groups
      // ==========================================
      if (res.resourceType === CloudResourceType.AWS_SECURITY_GROUP) {
        if (cfg.allowsAllTrafficFromInternet === true) {
          findings.push({
            ruleId: 'AWS-SG-ALL-TRAFFIC',
            nativeId: res.nativeId,
            resourceName: res.name,
            resourceType: res.resourceType,
            region: res.region,
            evidence: {
              groupId: cfg.groupId ?? res.name,
              protocol: '-1',
              cidr: '0.0.0.0/0',
            },
          });
        }
        if (cfg.allowsSshFromInternet === true) {
          findings.push({
            ruleId: 'AWS-SG-SSH-OPEN',
            nativeId: res.nativeId,
            resourceName: res.name,
            resourceType: res.resourceType,
            region: res.region,
            evidence: {
              groupId: cfg.groupId ?? res.name,
              port: 22,
              protocol: 'tcp',
              cidr: '0.0.0.0/0',
            },
          });
        }
        if (cfg.allowsRdpFromInternet === true) {
          findings.push({
            ruleId: 'AWS-SG-RDP-OPEN',
            nativeId: res.nativeId,
            resourceName: res.name,
            resourceType: res.resourceType,
            region: res.region,
            evidence: {
              groupId: cfg.groupId ?? res.name,
              port: 3389,
              protocol: 'tcp',
              cidr: '0.0.0.0/0',
            },
          });
        }
      }

      // ==========================================
      // 4. VPC
      // ==========================================
      if (res.resourceType === CloudResourceType.AWS_VPC) {
        if (cfg.flowLogsEnabled === false) {
          findings.push({
            ruleId: 'AWS-VPC-FLOW-LOGS',
            nativeId: res.nativeId,
            resourceName: res.name,
            resourceType: res.resourceType,
            region: res.region,
            evidence: {
              vpcId: cfg.vpcId ?? res.name,
              flowLogsEnabled: false,
            },
          });
        }
      }

      // ==========================================
      // 5. EC2 Instances & EBS
      // ==========================================
      if (res.resourceType === CloudResourceType.AWS_EC2_INSTANCE) {
        if (cfg.imdsv1Enabled === true) {
          findings.push({
            ruleId: 'AWS-EC2-IMDSV1-ENABLED',
            nativeId: res.nativeId,
            resourceName: res.name,
            resourceType: res.resourceType,
            region: res.region,
            evidence: {
              instanceId: cfg.instanceId ?? res.name,
              httpTokens: cfg.httpTokens ?? 'optional',
            },
          });
        }

        if (cfg.hasUnencryptedVolume === true) {
          findings.push({
            ruleId: 'AWS-EBS-UNENCRYPTED',
            nativeId: res.nativeId,
            resourceName: res.name,
            resourceType: res.resourceType,
            region: res.region,
            evidence: {
              instanceId: cfg.instanceId ?? res.name,
              unencryptedVolumeIds: cfg.unencryptedVolumeIds ?? [],
            },
          });
        }

        if (cfg.hasPublicIp === true) {
          findings.push({
            ruleId: 'AWS-EC2-PUBLIC-IP',
            nativeId: res.nativeId,
            resourceName: res.name,
            resourceType: res.resourceType,
            region: res.region,
            evidence: {
              instanceId: cfg.instanceId ?? res.name,
              publicIpAddress: cfg.publicIpAddress ?? 'exposed',
            },
          });
        }
      }

      // ==========================================
      // 6. RDS Instances
      // ==========================================
      if (res.resourceType === CloudResourceType.AWS_RDS_INSTANCE) {
        if (cfg.publiclyAccessible === true) {
          findings.push({
            ruleId: 'AWS-RDS-PUBLIC-ACCESS',
            nativeId: res.nativeId,
            resourceName: res.name,
            resourceType: res.resourceType,
            region: res.region,
            evidence: {
              dbInstanceIdentifier: res.name,
              engine: cfg.engine,
              publiclyAccessible: true,
            },
          });
        }

        if (cfg.storageEncrypted === false) {
          findings.push({
            ruleId: 'AWS-RDS-UNENCRYPTED',
            nativeId: res.nativeId,
            resourceName: res.name,
            resourceType: res.resourceType,
            region: res.region,
            evidence: {
              dbInstanceIdentifier: res.name,
              engine: cfg.engine,
              storageEncrypted: false,
            },
          });
        }

        if (Number(cfg.backupRetentionPeriod ?? 7) === 0) {
          findings.push({
            ruleId: 'AWS-RDS-NO-BACKUP',
            nativeId: res.nativeId,
            resourceName: res.name,
            resourceType: res.resourceType,
            region: res.region,
            evidence: {
              dbInstanceIdentifier: res.name,
              backupRetentionPeriod: 0,
            },
          });
        }
      }

      // ==========================================
      // 7. CloudTrail & GuardDuty
      // ==========================================
      if (res.resourceType === CloudResourceType.AWS_CLOUDTRAIL) {
        if (
          cfg.serviceType === 'CLOUDTRAIL' &&
          (cfg.isMultiRegionTrail === false || cfg.logFileValidationEnabled === false)
        ) {
          findings.push({
            ruleId: 'AWS-TRAIL-DISABLED',
            nativeId: res.nativeId,
            resourceName: res.name,
            resourceType: res.resourceType,
            region: res.region,
            evidence: {
              trailName: res.name,
              isMultiRegionTrail: Boolean(cfg.isMultiRegionTrail),
              logFileValidationEnabled: Boolean(cfg.logFileValidationEnabled),
            },
          });
        }

        if (cfg.serviceType === 'GUARDDUTY' && cfg.detectorEnabled === false) {
          findings.push({
            ruleId: 'AWS-GUARDDUTY-OFF',
            nativeId: res.nativeId,
            resourceName: res.name,
            resourceType: res.resourceType,
            region: res.region,
            evidence: {
              region: res.region,
              detectorEnabled: false,
            },
          });
        }
      }
    }

    return findings;
  }

  private async collectIamResources(
    accountId: string,
    credentials: AwsCredentials,
  ): Promise<DiscoveredCloudResource[]> {
    const resources: DiscoveredCloudResource[] = [];

    // 1.1 GetAccountSummary para Root MFA
    const summaryRes = await this.awsConnector.executeSignedXmlRequest({
      method: 'POST',
      url: 'https://iam.amazonaws.com/',
      region: 'us-east-1',
      service: 'iam',
      credentials,
      headers: { 'content-type': 'application/x-www-form-urlencoded; charset=utf-8' },
      body: 'Action=GetAccountSummary&Version=2010-05-08',
    });

    if (summaryRes.ok) {
      const entries = toArray(
        summaryRes.data?.GetAccountSummaryResponse?.GetAccountSummaryResult?.SummaryMap?.entry,
      );
      const mfaEntry = entries.find((e: any) => e?.key === 'AccountMFAEnabled');
      const rootMfaEnabled = String(mfaEntry?.value ?? '0') === '1';

      resources.push({
        nativeId: `arn:aws:iam::${accountId}:root`,
        name: 'root',
        resourceType: CloudResourceType.AWS_IAM_USER,
        region: 'global',
        configuration: {
          isRootAccount: true,
          accountMfaEnabled: rootMfaEnabled,
        },
        tags: { AccountType: 'Root' },
      });
    }

    // 1.2 ListUsers
    const usersRes = await this.awsConnector.executeSignedXmlRequest({
      method: 'POST',
      url: 'https://iam.amazonaws.com/',
      region: 'us-east-1',
      service: 'iam',
      credentials,
      headers: { 'content-type': 'application/x-www-form-urlencoded; charset=utf-8' },
      body: 'Action=ListUsers&Version=2010-05-08',
    });

    if (usersRes.ok) {
      const users = toArray(
        usersRes.data?.ListUsersResponse?.ListUsersResult?.Users?.member,
      );

      for (const u of users.slice(0, 25)) {
        const userName = String(u?.UserName ?? '');
        const userArn = String(u?.Arn ?? `arn:aws:iam::${accountId}:user/${userName}`);
        if (!userName) continue;

        const [mfaRes, keysRes, policiesRes] = await Promise.all([
          this.awsConnector.executeSignedXmlRequest({
            method: 'POST',
            url: 'https://iam.amazonaws.com/',
            region: 'us-east-1',
            service: 'iam',
            credentials,
            headers: { 'content-type': 'application/x-www-form-urlencoded; charset=utf-8' },
            body: new URLSearchParams({
              Action: 'ListMFADevices',
              UserName: userName,
              Version: '2010-05-08',
            }).toString(),
          }),
          this.awsConnector.executeSignedXmlRequest({
            method: 'POST',
            url: 'https://iam.amazonaws.com/',
            region: 'us-east-1',
            service: 'iam',
            credentials,
            headers: { 'content-type': 'application/x-www-form-urlencoded; charset=utf-8' },
            body: new URLSearchParams({
              Action: 'ListAccessKeys',
              UserName: userName,
              Version: '2010-05-08',
            }).toString(),
          }),
          this.awsConnector.executeSignedXmlRequest({
            method: 'POST',
            url: 'https://iam.amazonaws.com/',
            region: 'us-east-1',
            service: 'iam',
            credentials,
            headers: { 'content-type': 'application/x-www-form-urlencoded; charset=utf-8' },
            body: new URLSearchParams({
              Action: 'ListAttachedUserPolicies',
              UserName: userName,
              Version: '2010-05-08',
            }).toString(),
          }),
        ]);

        const mfaDevices = toArray(
          mfaRes.data?.ListMFADevicesResponse?.ListMFADevicesResult?.MFADevices?.member,
        );
        const accessKeys = toArray(
          keysRes.data?.ListAccessKeysResponse?.ListAccessKeysResult?.AccessKeyMetadata?.member,
        ).filter((k: any) => k?.Status === 'Active');

        const attachedPolicies = toArray(
          policiesRes.data?.ListAttachedUserPoliciesResponse?.ListAttachedUserPoliciesResult
            ?.AttachedPolicies?.member,
        ).map((p: any) => String(p?.PolicyName ?? ''));

        const oldestKey = accessKeys[0];
        const hasAdminPolicy = attachedPolicies.some((p) =>
          p.toLowerCase().includes('administratoraccess'),
        );

        resources.push({
          nativeId: userArn,
          name: userName,
          resourceType: CloudResourceType.AWS_IAM_USER,
          region: 'global',
          configuration: {
            isRootAccount: false,
            hasConsolePassword: Boolean(u?.PasswordLastUsed) || mfaDevices.length === 0,
            mfaEnabled: mfaDevices.length > 0,
            oldestActiveKeyId: oldestKey?.AccessKeyId ?? null,
            oldestActiveKeyCreatedAt: oldestKey?.CreateDate ?? null,
            attachedPolicies,
            hasAdminPolicy,
          },
        });
      }
    }

    return resources;
  }

  private async collectS3Resources(
    accountId: string,
    credentials: AwsCredentials,
  ): Promise<DiscoveredCloudResource[]> {
    const resources: DiscoveredCloudResource[] = [];

    const listRes = await this.awsConnector.executeSignedXmlRequest({
      method: 'GET',
      url: 'https://s3.amazonaws.com/',
      region: 'us-east-1',
      service: 's3',
      credentials,
    });

    if (!listRes.ok) return resources;

    const buckets = toArray(
      listRes.data?.ListAllMyBucketsResult?.Buckets?.Bucket,
    );

    for (const b of buckets.slice(0, 25)) {
      const bucketName = String(b?.Name ?? '');
      if (!bucketName) continue;

      const [pabRes, encRes, logRes] = await Promise.all([
        this.awsConnector.executeSignedXmlRequest({
          method: 'GET',
          url: `https://${bucketName}.s3.amazonaws.com/?publicAccessBlock`,
          region: 'us-east-1',
          service: 's3',
          credentials,
        }),
        this.awsConnector.executeSignedXmlRequest({
          method: 'GET',
          url: `https://${bucketName}.s3.amazonaws.com/?encryption`,
          region: 'us-east-1',
          service: 's3',
          credentials,
        }),
        this.awsConnector.executeSignedXmlRequest({
          method: 'GET',
          url: `https://${bucketName}.s3.amazonaws.com/?logging`,
          region: 'us-east-1',
          service: 's3',
          credentials,
        }),
      ]);

      const pab = pabRes.data?.PublicAccessBlockConfiguration;
      const publicAccessBlocked =
        pabRes.ok &&
        String(pab?.BlockPublicAcls) === 'true' &&
        String(pab?.IgnorePublicAcls) === 'true' &&
        String(pab?.BlockPublicPolicy) === 'true' &&
        String(pab?.RestrictPublicBuckets) === 'true';

      const defaultEncryptionEnabled =
        encRes.ok &&
        Boolean(encRes.data?.ServerSideEncryptionConfiguration?.Rule);

      const accessLoggingEnabled =
        logRes.ok &&
        Boolean(logRes.data?.BucketLoggingStatus?.LoggingEnabled);

      resources.push({
        nativeId: `arn:aws:s3:::${bucketName}`,
        name: bucketName,
        resourceType: CloudResourceType.AWS_S3_BUCKET,
        region: 'us-east-1',
        configuration: {
          accountId,
          publicAccessBlocked,
          publicAccessBlockConfig: pab ?? null,
          defaultEncryptionEnabled,
          accessLoggingEnabled,
        },
      });
    }

    return resources;
  }

  private async collectEc2AndNetworkResources(
    accountId: string,
    region: string,
    credentials: AwsCredentials,
  ): Promise<DiscoveredCloudResource[]> {
    const resources: DiscoveredCloudResource[] = [];
    const ec2Endpoint = `https://ec2.${region}.amazonaws.com/`;

    // 1. Security Groups
    const sgRes = await this.awsConnector.executeSignedXmlRequest({
      method: 'POST',
      url: ec2Endpoint,
      region,
      service: 'ec2',
      credentials,
      headers: { 'content-type': 'application/x-www-form-urlencoded; charset=utf-8' },
      body: 'Action=DescribeSecurityGroups&Version=2016-11-15',
    });

    if (sgRes.ok) {
      const groups = toArray(
        sgRes.data?.DescribeSecurityGroupsResponse?.securityGroupInfo?.item,
      );
      for (const g of groups) {
        const groupId = String(g?.groupId ?? '');
        const groupName = String(g?.groupName ?? groupId);
        if (!groupId) continue;

        const perms = toArray(g?.ipPermissions?.item);
        let allowsSshFromInternet = false;
        let allowsRdpFromInternet = false;
        let allowsAllTrafficFromInternet = false;

        for (const p of perms) {
          const proto = String(p?.ipProtocol ?? '');
          const fromPort = Number(p?.fromPort ?? -1);
          const toPort = Number(p?.toPort ?? -1);
          const cidrs = [
            ...toArray(p?.ipRanges?.item).map((r: any) => String(r?.cidrIp ?? '')),
            ...toArray(p?.ipv6Ranges?.item).map((r: any) => String(r?.cidrIpv6 ?? '')),
          ];
          const isOpenToInternet = cidrs.some((c) => c === '0.0.0.0/0' || c === '::/0');
          if (!isOpenToInternet) continue;

          if (proto === '-1') {
            allowsAllTrafficFromInternet = true;
          } else if (fromPort <= 22 && toPort >= 22) {
            allowsSshFromInternet = true;
          } else if (fromPort <= 3389 && toPort >= 3389) {
            allowsRdpFromInternet = true;
          }
        }

        resources.push({
          nativeId: `arn:aws:ec2:${region}:${accountId}:security-group/${groupId}`,
          name: `${groupName} (${groupId})`,
          resourceType: CloudResourceType.AWS_SECURITY_GROUP,
          region,
          configuration: {
            groupId,
            groupName,
            vpcId: g?.vpcId ?? null,
            allowsSshFromInternet,
            allowsRdpFromInternet,
            allowsAllTrafficFromInternet,
          },
        });
      }
    }

    // 2. VPCs & Flow Logs
    const [vpcRes, flowRes] = await Promise.all([
      this.awsConnector.executeSignedXmlRequest({
        method: 'POST',
        url: ec2Endpoint,
        region,
        service: 'ec2',
        credentials,
        headers: { 'content-type': 'application/x-www-form-urlencoded; charset=utf-8' },
        body: 'Action=DescribeVpcs&Version=2016-11-15',
      }),
      this.awsConnector.executeSignedXmlRequest({
        method: 'POST',
        url: ec2Endpoint,
        region,
        service: 'ec2',
        credentials,
        headers: { 'content-type': 'application/x-www-form-urlencoded; charset=utf-8' },
        body: 'Action=DescribeFlowLogs&Version=2016-11-15',
      }),
    ]);

    if (vpcRes.ok) {
      const vpcs = toArray(vpcRes.data?.DescribeVpcsResponse?.vpcSet?.item);
      const flowLogs = toArray(
        flowRes.data?.DescribeFlowLogsResponse?.flowLogSet?.item,
      );
      const vpcWithFlowLogs = new Set(
        flowLogs.map((fl: any) => String(fl?.resourceId ?? '')),
      );

      for (const v of vpcs) {
        const vpcId = String(v?.vpcId ?? '');
        if (!vpcId) continue;

        resources.push({
          nativeId: `arn:aws:ec2:${region}:${accountId}:vpc/${vpcId}`,
          name: vpcId,
          resourceType: CloudResourceType.AWS_VPC,
          region,
          configuration: {
            vpcId,
            cidrBlock: v?.cidrBlock ?? null,
            flowLogsEnabled: vpcWithFlowLogs.has(vpcId),
          },
        });
      }
    }

    // 3. EC2 Instances & EBS Volumes
    const [instRes, volRes] = await Promise.all([
      this.awsConnector.executeSignedXmlRequest({
        method: 'POST',
        url: ec2Endpoint,
        region,
        service: 'ec2',
        credentials,
        headers: { 'content-type': 'application/x-www-form-urlencoded; charset=utf-8' },
        body: 'Action=DescribeInstances&Version=2016-11-15',
      }),
      this.awsConnector.executeSignedXmlRequest({
        method: 'POST',
        url: ec2Endpoint,
        region,
        service: 'ec2',
        credentials,
        headers: { 'content-type': 'application/x-www-form-urlencoded; charset=utf-8' },
        body: 'Action=DescribeVolumes&Version=2016-11-15',
      }),
    ]);

    const unencryptedVolumesByInstance = new Map<string, string[]>();
    if (volRes.ok) {
      const volumes = toArray(volRes.data?.DescribeVolumesResponse?.volumeSet?.item);
      for (const vol of volumes) {
        const encrypted = String(vol?.encrypted ?? 'false') === 'true';
        if (!encrypted) {
          const volId = String(vol?.volumeId ?? '');
          const attachments = toArray(vol?.attachmentSet?.item);
          for (const att of attachments) {
            const instId = String(att?.instanceId ?? '');
            if (instId && volId) {
              const list = unencryptedVolumesByInstance.get(instId) ?? [];
              list.push(volId);
              unencryptedVolumesByInstance.set(instId, list);
            }
          }
        }
      }
    }

    if (instRes.ok) {
      const reservations = toArray(
        instRes.data?.DescribeInstancesResponse?.reservationSet?.item,
      );
      for (const r of reservations) {
        const instances = toArray(r?.instancesSet?.item);
        for (const inst of instances) {
          const instanceId = String(inst?.instanceId ?? '');
          if (!instanceId) continue;

          const httpTokens = String(inst?.metadataOptions?.httpTokens ?? 'optional');
          const publicIpAddress = inst?.ipAddress ? String(inst.ipAddress) : null;
          const unencryptedVols = unencryptedVolumesByInstance.get(instanceId) ?? [];

          resources.push({
            nativeId: `arn:aws:ec2:${region}:${accountId}:instance/${instanceId}`,
            name: instanceId,
            resourceType: CloudResourceType.AWS_EC2_INSTANCE,
            region,
            configuration: {
              instanceId,
              instanceType: inst?.instanceType ?? 't3.micro',
              httpTokens,
              imdsv1Enabled: httpTokens !== 'required',
              hasPublicIp: Boolean(publicIpAddress),
              publicIpAddress,
              hasUnencryptedVolume: unencryptedVols.length > 0,
              unencryptedVolumeIds: unencryptedVols,
            },
          });
        }
      }
    }

    return resources;
  }

  private async collectRdsResources(
    accountId: string,
    region: string,
    credentials: AwsCredentials,
  ): Promise<DiscoveredCloudResource[]> {
    const resources: DiscoveredCloudResource[] = [];
    const rdsEndpoint = `https://rds.${region}.amazonaws.com/`;

    const rdsRes = await this.awsConnector.executeSignedXmlRequest({
      method: 'POST',
      url: rdsEndpoint,
      region,
      service: 'rds',
      credentials,
      headers: { 'content-type': 'application/x-www-form-urlencoded; charset=utf-8' },
      body: 'Action=DescribeDBInstances&Version=2014-10-31',
    });

    if (!rdsRes.ok) return resources;

    const dbs = toArray(
      rdsRes.data?.DescribeDBInstancesResponse?.DescribeDBInstancesResult?.DBInstances
        ?.DBInstance,
    );

    for (const db of dbs) {
      const dbId = String(db?.DBInstanceIdentifier ?? '');
      if (!dbId) continue;

      const arn = String(
        db?.DBInstanceArn ?? `arn:aws:rds:${region}:${accountId}:db:${dbId}`,
      );

      resources.push({
        nativeId: arn,
        name: dbId,
        resourceType: CloudResourceType.AWS_RDS_INSTANCE,
        region,
        configuration: {
          dbInstanceIdentifier: dbId,
          engine: db?.Engine ?? 'postgres',
          publiclyAccessible: String(db?.PubliclyAccessible ?? 'false') === 'true',
          storageEncrypted: String(db?.StorageEncrypted ?? 'false') === 'true',
          backupRetentionPeriod: Number(db?.BackupRetentionPeriod ?? 0),
        },
      });
    }

    return resources;
  }

  private async collectLoggingResources(
    accountId: string,
    region: string,
    credentials: AwsCredentials,
  ): Promise<DiscoveredCloudResource[]> {
    const resources: DiscoveredCloudResource[] = [];

    // CloudTrail DescribeTrails
    const ctRes = await this.awsConnector.executeSignedXmlRequest({
      method: 'POST',
      url: `https://cloudtrail.${region}.amazonaws.com/`,
      region,
      service: 'cloudtrail',
      credentials,
      headers: {
        'content-type': 'application/x-amz-json-1.1',
        'x-amz-target': 'com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.DescribeTrails',
      },
      body: JSON.stringify({ includeShadowTrails: true }),
    });

    const trailList = Array.isArray(ctRes.data?.trailList) ? ctRes.data.trailList : [];
    const validTrail = trailList.find(
      (t: any) => t?.IsMultiRegionTrail === true && t?.LogFileValidationEnabled === true,
    );

    resources.push({
      nativeId: validTrail?.TrailARN ?? `arn:aws:cloudtrail:${region}:${accountId}:trail/organization-trail`,
      name: validTrail?.Name ?? `cloudtrail-${region}`,
      resourceType: CloudResourceType.AWS_CLOUDTRAIL,
      region,
      configuration: {
        serviceType: 'CLOUDTRAIL',
        isMultiRegionTrail: Boolean(validTrail?.IsMultiRegionTrail),
        logFileValidationEnabled: Boolean(validTrail?.LogFileValidationEnabled),
      },
    });

    // GuardDuty ListDetectors
    const gdRes = await this.awsConnector.executeSignedXmlRequest({
      method: 'GET',
      url: `https://guardduty.${region}.amazonaws.com/detector`,
      region,
      service: 'guardduty',
      credentials,
    });

    const detectorIds = Array.isArray(gdRes.data?.detectorIds)
      ? gdRes.data.detectorIds
      : [];

    resources.push({
      nativeId: `arn:aws:guardduty:${region}:${accountId}:detector/${detectorIds[0] ?? 'none'}`,
      name: `guardduty-${region}`,
      resourceType: CloudResourceType.AWS_CLOUDTRAIL,
      region,
      configuration: {
        serviceType: 'GUARDDUTY',
        detectorEnabled: detectorIds.length > 0,
      },
    });

    return resources;
  }

  /**
   * Genera un inventario representativo de AWS para modo simulación / sandbox (`000000000000`),
   * permitiendo probar el flujo completo de CSPM sin requerir credenciales facturables.
   */
  buildBenchmarkInventory(
    accountId: string,
    primaryRegion: string,
  ): DiscoveredCloudResource[] {
    return [
      {
        nativeId: `arn:aws:iam::${accountId}:root`,
        name: 'root',
        resourceType: CloudResourceType.AWS_IAM_USER,
        region: 'global',
        configuration: {
          isRootAccount: true,
          accountMfaEnabled: false,
        },
        tags: { Environment: 'production', Criticality: 'critical' },
      },
      {
        nativeId: `arn:aws:iam::${accountId}:user/ci-deploy-legacy`,
        name: 'ci-deploy-legacy',
        resourceType: CloudResourceType.AWS_IAM_USER,
        region: 'global',
        configuration: {
          isRootAccount: false,
          hasConsolePassword: true,
          mfaEnabled: false,
          oldestActiveKeyId: 'AKIAIOSFODNN7EXAMPLE',
          oldestActiveKeyAgeDays: 142,
          attachedPolicies: ['AdministratorAccess'],
          hasAdminPolicy: true,
        },
        tags: { Team: 'DevOps', Purpose: 'CI/CD' },
      },
      {
        nativeId: `arn:aws:s3:::corp-public-exports-${accountId.slice(-4)}`,
        name: `corp-public-exports-${accountId.slice(-4)}`,
        resourceType: CloudResourceType.AWS_S3_BUCKET,
        region: primaryRegion,
        configuration: {
          publicAccessBlocked: false,
          defaultEncryptionEnabled: false,
          accessLoggingEnabled: false,
        },
        tags: { DataClassification: 'Confidential', Environment: 'production' },
      },
      {
        nativeId: `arn:aws:ec2:${primaryRegion}:${accountId}:security-group/sg-0a1b2c3d4e5f60001`,
        name: 'prod-bastion-sg (sg-0a1b2c3d4e5f60001)',
        resourceType: CloudResourceType.AWS_SECURITY_GROUP,
        region: primaryRegion,
        configuration: {
          groupId: 'sg-0a1b2c3d4e5f60001',
          groupName: 'prod-bastion-sg',
          allowsSshFromInternet: true,
          allowsRdpFromInternet: false,
          allowsAllTrafficFromInternet: false,
        },
        tags: { Layer: 'Perimeter' },
      },
      {
        nativeId: `arn:aws:ec2:${primaryRegion}:${accountId}:vpc/vpc-09988776655443322`,
        name: 'vpc-09988776655443322',
        resourceType: CloudResourceType.AWS_VPC,
        region: primaryRegion,
        configuration: {
          vpcId: 'vpc-09988776655443322',
          cidrBlock: '10.10.0.0/16',
          flowLogsEnabled: false,
        },
        tags: { Name: 'prod-main-vpc' },
      },
      {
        nativeId: `arn:aws:ec2:${primaryRegion}:${accountId}:instance/i-0123456789abcdef0`,
        name: 'prod-api-worker-01 (i-0123456789abcdef0)',
        resourceType: CloudResourceType.AWS_EC2_INSTANCE,
        region: primaryRegion,
        configuration: {
          instanceId: 'i-0123456789abcdef0',
          instanceType: 't3.large',
          httpTokens: 'optional',
          imdsv1Enabled: true,
          hasPublicIp: true,
          publicIpAddress: '54.210.114.89',
          hasUnencryptedVolume: true,
          unencryptedVolumeIds: ['vol-0abc123def4567890'],
        },
        tags: { Role: 'backend-worker', Environment: 'production' },
      },
      {
        nativeId: `arn:aws:rds:${primaryRegion}:${accountId}:db:prod-customers-pg`,
        name: 'prod-customers-pg',
        resourceType: CloudResourceType.AWS_RDS_INSTANCE,
        region: primaryRegion,
        configuration: {
          dbInstanceIdentifier: 'prod-customers-pg',
          engine: 'postgres',
          publiclyAccessible: true,
          storageEncrypted: false,
          backupRetentionPeriod: 0,
        },
        tags: { Tier: 'Database', Compliance: 'PCI' },
      },
      {
        nativeId: `arn:aws:cloudtrail:${primaryRegion}:${accountId}:trail/organization-trail`,
        name: `cloudtrail-${primaryRegion}`,
        resourceType: CloudResourceType.AWS_CLOUDTRAIL,
        region: primaryRegion,
        configuration: {
          serviceType: 'CLOUDTRAIL',
          isMultiRegionTrail: false,
          logFileValidationEnabled: false,
        },
      },
      {
        nativeId: `arn:aws:guardduty:${primaryRegion}:${accountId}:detector/none`,
        name: `guardduty-${primaryRegion}`,
        resourceType: CloudResourceType.AWS_CLOUDTRAIL,
        region: primaryRegion,
        configuration: {
          serviceType: 'GUARDDUTY',
          detectorEnabled: false,
        },
      },
    ];
  }
}
