import { CloudProvider, CloudResourceType } from '@prisma/client';
import { AzureConnectorService } from '../connectors/azure-connector.service';
import { AzureCspmEvaluatorService } from './azure-cspm.evaluator';
import { DiscoveredCloudResource } from './cspm-evaluator.types';

describe('AzureCspmEvaluatorService', () => {
  let evaluator: AzureCspmEvaluatorService;
  let azureConnectorMock: {
    acquireManagementToken: jest.Mock;
    executeArmGet: jest.Mock;
  };

  beforeEach(() => {
    azureConnectorMock = {
      acquireManagementToken: jest.fn(),
      executeArmGet: jest.fn(),
    };
    evaluator = new AzureCspmEvaluatorService(
      azureConnectorMock as unknown as AzureConnectorService,
    );
  });

  it('evalúa las 12 reglas CSPM de Azure cuando los recursos presentan malas configuraciones', () => {
    const subscriptionId = '11111111-2222-3333-4444-555555555555';
    const resources: DiscoveredCloudResource[] = [
      ...evaluator.buildBenchmarkInventory(subscriptionId, 'eastus'),
      {
        nativeId: `/subscriptions/${subscriptionId}/providers/Microsoft.Authorization/adminPolicy`,
        name: 'Global-Admin-MFA-Policy',
        resourceType: CloudResourceType.OTHER,
        region: 'global',
        configuration: {
          subType: 'ENTRA_ADMIN_POLICY',
          adminMfaEnforced: false,
        },
      },
    ];

    const findings = evaluator.evaluateInventoryRules(subscriptionId, resources);
    const detectedRuleIds = new Set(findings.map((f) => f.ruleId));

    expect(detectedRuleIds).toEqual(
      new Set([
        'AZ-IAM-GLOBAL-ADMIN-MFA',
        'AZ-IAM-CUSTOM-OWNER',
        'AZ-BLOB-PUBLIC-ACCESS',
        'AZ-STORAGE-NO-HTTPS',
        'AZ-STORAGE-NO-TLS12',
        'AZ-NSG-SSH-OPEN',
        'AZ-NSG-RDP-OPEN',
        'AZ-VM-UNENCRYPTED-DISK',
        'AZ-VM-PASSWORD-AUTH',
        'AZ-SQL-PUBLIC-ACCESS',
        'AZ-SQL-TDE-DISABLED',
        'AZ-ACTIVITY-LOG-OFF',
      ]),
    );
  });

  it('no genera hallazgos cuando todos los recursos Azure cumplen las líneas base de seguridad', () => {
    const subscriptionId = '11111111-2222-3333-4444-555555555555';
    const compliantResources: DiscoveredCloudResource[] = [
      {
        nativeId: `/subscriptions/${subscriptionId}/providers/Microsoft.Authorization/adminPolicy`,
        name: 'Global-Admin-MFA-Policy',
        resourceType: CloudResourceType.OTHER,
        region: 'global',
        configuration: {
          subType: 'ENTRA_ADMIN_POLICY',
          adminMfaEnforced: true,
        },
      },
      {
        nativeId: `/subscriptions/${subscriptionId}/providers/Microsoft.Storage/storageAccounts/stsecure01`,
        name: 'stsecure01',
        resourceType: CloudResourceType.AZURE_STORAGE_ACCOUNT,
        region: 'eastus',
        configuration: {
          allowBlobPublicAccess: false,
          supportsHttpsTrafficOnly: true,
          minimumTlsVersion: 'TLS1_2',
        },
      },
      {
        nativeId: `/subscriptions/${subscriptionId}/providers/Microsoft.Network/networkSecurityGroups/nsg-secure`,
        name: 'nsg-secure',
        resourceType: CloudResourceType.AZURE_NSG,
        region: 'eastus',
        configuration: {
          allowsSshFromInternet: false,
          allowsRdpFromInternet: false,
        },
      },
      {
        nativeId: `/subscriptions/${subscriptionId}/providers/Microsoft.Compute/virtualMachines/vm-secure`,
        name: 'vm-secure',
        resourceType: CloudResourceType.AZURE_VM,
        region: 'eastus',
        configuration: {
          diskEncryptionEnabled: true,
          isLinux: true,
          disablePasswordAuthentication: true,
        },
      },
      {
        nativeId: `/subscriptions/${subscriptionId}/providers/Microsoft.Sql/servers/sql-secure`,
        name: 'sql-secure',
        resourceType: CloudResourceType.AZURE_SQL_DATABASE,
        region: 'eastus',
        configuration: {
          publicNetworkAccessEnabled: false,
          tdeEnabled: true,
        },
      },
      {
        nativeId: `/subscriptions/${subscriptionId}/providers/Microsoft.Insights/diagnosticSettings/activity-log`,
        name: 'activity-log',
        resourceType: CloudResourceType.AZURE_ACTIVITY_LOG,
        region: 'global',
        configuration: {
          activityLogExportEnabled: true,
        },
      },
    ];

    const findings = evaluator.evaluateInventoryRules(
      subscriptionId,
      compliantResources,
    );
    expect(findings).toHaveLength(0);
  });

  it('ejecuta evaluateSubscription en modo simulación cuando simulate=true', async () => {
    const result = await evaluator.evaluateSubscription({
      authInput: {
        subscriptionId: '11111111-2222-3333-4444-555555555555',
        tenantId: 'tenant-1',
        clientId: 'client-1',
        clientSecret: 'secret-1',
      },
      monitoredRegions: ['eastus'],
      simulate: true,
    });

    expect(result.provider).toBe(CloudProvider.AZURE);
    expect(result.simulated).toBe(true);
    expect(result.evaluatedRulesCount).toBe(12);
    expect(result.resources.length).toBeGreaterThan(0);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(azureConnectorMock.acquireManagementToken).not.toHaveBeenCalled();
  });
});
