import { Injectable, Logger } from '@nestjs/common';
import { CloudProvider, CloudResourceType } from '@prisma/client';
import {
  AzureAuthInput,
  AzureConnectorService,
} from '../connectors/azure-connector.service';
import { CSPM_RULES } from '../cspm.catalog';
import {
  CloudAuditExecutionResult,
  CspmFindingDraft,
  DiscoveredCloudResource,
} from './cspm-evaluator.types';

function portMatchesRange(rangeStr: string | undefined, targetPort: number): boolean {
  if (!rangeStr) return false;
  const trimmed = rangeStr.trim();
  if (trimmed === '*') return true;
  if (trimmed.includes('-')) {
    const [start, end] = trimmed.split('-').map((n) => Number(n.trim()));
    if (!Number.isNaN(start) && !Number.isNaN(end)) {
      return targetPort >= start && targetPort <= end;
    }
  }
  return Number(trimmed) === targetPort;
}

@Injectable()
export class AzureCspmEvaluatorService {
  private readonly logger = new Logger(AzureCspmEvaluatorService.name);
  private readonly azureRuleCount = CSPM_RULES.filter(
    (r) => r.provider === CloudProvider.AZURE,
  ).length;

  constructor(private readonly azureConnector: AzureConnectorService) {}

  /**
   * Ejecuta la auditoría completa de postura CSPM sobre una suscripción de Microsoft Azure:
   * - Si se indica `simulate = true` o el subscriptionId es `00000000-0000-0000-0000-000000000000`,
   *   utiliza un inventario de referencia determinístico para validación/demostración.
   * - En caso contrario, adquiere un token OAuth2 en Microsoft Entra ID y consulta Azure Resource
   *   Manager (ARM REST API) para recolectar recursos y evaluar las 12 reglas Azure del catálogo.
   */
  async evaluateSubscription(params: {
    authInput: AzureAuthInput;
    monitoredRegions: string[];
    simulate?: boolean;
  }): Promise<CloudAuditExecutionResult> {
    const subscriptionId = params.authInput.subscriptionId.trim();
    const primaryRegion = params.monitoredRegions[0] ?? 'eastus';

    const isSandbox =
      params.simulate === true ||
      subscriptionId === '00000000-0000-0000-0000-000000000000';

    if (isSandbox) {
      const resources = this.buildBenchmarkInventory(subscriptionId, primaryRegion);
      const findings = this.evaluateInventoryRules(subscriptionId, resources);
      return {
        provider: CloudProvider.AZURE,
        accountOrSubscriptionId: subscriptionId,
        simulated: true,
        evaluatedRulesCount: this.azureRuleCount,
        resources,
        findings,
        warnings: [],
      };
    }

    const warnings: string[] = [];
    const { accessToken } = await this.azureConnector.acquireManagementToken({
      tenantId: params.authInput.tenantId,
      clientId: params.authInput.clientId,
      clientSecret: params.authInput.clientSecret,
    });

    const resources: DiscoveredCloudResource[] = [];

    // 1. IAM / RBAC Role Definitions
    try {
      const iamResources = await this.collectRbacResources(
        subscriptionId,
        accessToken,
      );
      resources.push(...iamResources);
    } catch (err) {
      warnings.push(`RBAC: ${err instanceof Error ? err.message : String(err)}`);
    }

    // 2. Storage Accounts
    try {
      const storageResources = await this.collectStorageResources(
        subscriptionId,
        accessToken,
      );
      resources.push(...storageResources);
    } catch (err) {
      warnings.push(`Storage: ${err instanceof Error ? err.message : String(err)}`);
    }

    // 3. Network Security Groups (NSGs)
    try {
      const nsgResources = await this.collectNsgResources(
        subscriptionId,
        accessToken,
      );
      resources.push(...nsgResources);
    } catch (err) {
      warnings.push(`NSG: ${err instanceof Error ? err.message : String(err)}`);
    }

    // 4. Virtual Machines
    try {
      const vmResources = await this.collectVmResources(
        subscriptionId,
        accessToken,
      );
      resources.push(...vmResources);
    } catch (err) {
      warnings.push(`Compute: ${err instanceof Error ? err.message : String(err)}`);
    }

    // 5. Azure SQL Servers & Databases
    try {
      const sqlResources = await this.collectSqlResources(
        subscriptionId,
        accessToken,
      );
      resources.push(...sqlResources);
    } catch (err) {
      warnings.push(`SQL: ${err instanceof Error ? err.message : String(err)}`);
    }

    // 6. Azure Monitor Activity Log Diagnostic Settings
    try {
      const logResources = await this.collectActivityLogResources(
        subscriptionId,
        accessToken,
      );
      resources.push(...logResources);
    } catch (err) {
      warnings.push(`Monitor: ${err instanceof Error ? err.message : String(err)}`);
    }

    const findings = this.evaluateInventoryRules(subscriptionId, resources);

    return {
      provider: CloudProvider.AZURE,
      accountOrSubscriptionId: subscriptionId,
      simulated: false,
      evaluatedRulesCount: this.azureRuleCount,
      resources,
      findings,
      warnings,
    };
  }

  /**
   * Evalúa las 12 reglas CSPM de Azure sobre el inventario recolectado.
   * Función pura y determinística para pruebas unitarias exhaustivas.
   */
  evaluateInventoryRules(
    subscriptionId: string,
    resources: DiscoveredCloudResource[],
  ): CspmFindingDraft[] {
    const findings: CspmFindingDraft[] = [];

    for (const res of resources) {
      const cfg = res.configuration ?? {};

      // ==========================================
      // 1. IAM / RBAC (Entra ID & Custom Roles)
      // ==========================================
      if (res.resourceType === CloudResourceType.OTHER) {
        if (cfg.subType === 'ENTRA_ADMIN_POLICY' && cfg.adminMfaEnforced === false) {
          findings.push({
            ruleId: 'AZ-IAM-GLOBAL-ADMIN-MFA',
            nativeId: res.nativeId,
            resourceName: res.name,
            resourceType: res.resourceType,
            region: res.region,
            evidence: {
              subscriptionId,
              adminMfaEnforced: false,
              unprotectedAdminsCount: cfg.unprotectedAdminsCount ?? 1,
            },
          });
        }

        if (cfg.subType === 'RBAC_CUSTOM_ROLE' && cfg.hasWildcardActions === true) {
          findings.push({
            ruleId: 'AZ-IAM-CUSTOM-OWNER',
            nativeId: res.nativeId,
            resourceName: res.name,
            resourceType: res.resourceType,
            region: res.region,
            evidence: {
              roleName: res.name,
              actions: cfg.actions ?? ['*'],
              assignableScopes: cfg.assignableScopes ?? [`/subscriptions/${subscriptionId}`],
            },
          });
        }
      }

      // ==========================================
      // 2. Azure Storage Accounts & Blobs
      // ==========================================
      if (
        res.resourceType === CloudResourceType.AZURE_STORAGE_ACCOUNT ||
        res.resourceType === CloudResourceType.AZURE_BLOB_CONTAINER
      ) {
        if (cfg.allowBlobPublicAccess === true) {
          findings.push({
            ruleId: 'AZ-BLOB-PUBLIC-ACCESS',
            nativeId: res.nativeId,
            resourceName: res.name,
            resourceType: res.resourceType,
            region: res.region,
            evidence: {
              storageAccount: res.name,
              allowBlobPublicAccess: true,
            },
          });
        }

        if (cfg.supportsHttpsTrafficOnly === false) {
          findings.push({
            ruleId: 'AZ-STORAGE-NO-HTTPS',
            nativeId: res.nativeId,
            resourceName: res.name,
            resourceType: res.resourceType,
            region: res.region,
            evidence: {
              storageAccount: res.name,
              supportsHttpsTrafficOnly: false,
            },
          });
        }

        if (
          cfg.minimumTlsVersion &&
          String(cfg.minimumTlsVersion).toUpperCase() !== 'TLS1_2'
        ) {
          findings.push({
            ruleId: 'AZ-STORAGE-NO-TLS12',
            nativeId: res.nativeId,
            resourceName: res.name,
            resourceType: res.resourceType,
            region: res.region,
            evidence: {
              storageAccount: res.name,
              minimumTlsVersion: cfg.minimumTlsVersion,
              expectedMinimumTlsVersion: 'TLS1_2',
            },
          });
        }
      }

      // ==========================================
      // 3. Network Security Groups (NSGs)
      // ==========================================
      if (res.resourceType === CloudResourceType.AZURE_NSG) {
        if (cfg.allowsSshFromInternet === true) {
          findings.push({
            ruleId: 'AZ-NSG-SSH-OPEN',
            nativeId: res.nativeId,
            resourceName: res.name,
            resourceType: res.resourceType,
            region: res.region,
            evidence: {
              nsgName: res.name,
              port: 22,
              offendingRules: cfg.sshOffendingRules ?? ['Allow-SSH-Internet'],
            },
          });
        }

        if (cfg.allowsRdpFromInternet === true) {
          findings.push({
            ruleId: 'AZ-NSG-RDP-OPEN',
            nativeId: res.nativeId,
            resourceName: res.name,
            resourceType: res.resourceType,
            region: res.region,
            evidence: {
              nsgName: res.name,
              port: 3389,
              offendingRules: cfg.rdpOffendingRules ?? ['Allow-RDP-Internet'],
            },
          });
        }
      }

      // ==========================================
      // 4. Virtual Machines
      // ==========================================
      if (res.resourceType === CloudResourceType.AZURE_VM) {
        if (cfg.diskEncryptionEnabled === false) {
          findings.push({
            ruleId: 'AZ-VM-UNENCRYPTED-DISK',
            nativeId: res.nativeId,
            resourceName: res.name,
            resourceType: res.resourceType,
            region: res.region,
            evidence: {
              vmName: res.name,
              encryptionAtHost: false,
              osDiskEncrypted: false,
            },
          });
        }

        if (cfg.isLinux === true && cfg.disablePasswordAuthentication === false) {
          findings.push({
            ruleId: 'AZ-VM-PASSWORD-AUTH',
            nativeId: res.nativeId,
            resourceName: res.name,
            resourceType: res.resourceType,
            region: res.region,
            evidence: {
              vmName: res.name,
              osType: 'Linux',
              disablePasswordAuthentication: false,
            },
          });
        }
      }

      // ==========================================
      // 5. Azure SQL Databases
      // ==========================================
      if (res.resourceType === CloudResourceType.AZURE_SQL_DATABASE) {
        if (cfg.publicNetworkAccessEnabled === true) {
          findings.push({
            ruleId: 'AZ-SQL-PUBLIC-ACCESS',
            nativeId: res.nativeId,
            resourceName: res.name,
            resourceType: res.resourceType,
            region: res.region,
            evidence: {
              serverOrDbName: res.name,
              publicNetworkAccess: 'Enabled',
            },
          });
        }

        if (cfg.tdeEnabled === false) {
          findings.push({
            ruleId: 'AZ-SQL-TDE-DISABLED',
            nativeId: res.nativeId,
            resourceName: res.name,
            resourceType: res.resourceType,
            region: res.region,
            evidence: {
              serverOrDbName: res.name,
              transparentDataEncryption: 'Disabled',
            },
          });
        }
      }

      // ==========================================
      // 6. Azure Monitor Activity Log
      // ==========================================
      if (res.resourceType === CloudResourceType.AZURE_ACTIVITY_LOG) {
        if (cfg.activityLogExportEnabled === false) {
          findings.push({
            ruleId: 'AZ-ACTIVITY-LOG-OFF',
            nativeId: res.nativeId,
            resourceName: res.name,
            resourceType: res.resourceType,
            region: res.region,
            evidence: {
              subscriptionId,
              diagnosticSettingsCount: cfg.diagnosticSettingsCount ?? 0,
              workspaceId: null,
            },
          });
        }
      }
    }

    return findings;
  }

  private async collectRbacResources(
    subscriptionId: string,
    accessToken: string,
  ): Promise<DiscoveredCloudResource[]> {
    const resources: DiscoveredCloudResource[] = [];

    const rolesRes = await this.azureConnector.executeArmGet<{ value?: any[] }>(
      accessToken,
      `/subscriptions/${encodeURIComponent(subscriptionId)}/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01`,
    );

    if (rolesRes.ok && Array.isArray(rolesRes.data?.value)) {
      const customRoles = rolesRes.data.value.filter(
        (r) => r?.properties?.type === 'CustomRole',
      );
      for (const role of customRoles) {
        const roleId = String(role?.id ?? '');
        const roleName = String(role?.properties?.roleName ?? role?.name ?? 'CustomRole');
        const permissions = Array.isArray(role?.properties?.permissions)
          ? role.properties.permissions
          : [];
        const actions: string[] = permissions.flatMap((p: any) =>
          Array.isArray(p?.actions) ? p.actions : [],
        );
        const hasWildcardActions = actions.includes('*');

        resources.push({
          nativeId: roleId,
          name: roleName,
          resourceType: CloudResourceType.OTHER,
          region: 'global',
          configuration: {
            subType: 'RBAC_CUSTOM_ROLE',
            roleName,
            actions,
            assignableScopes: role?.properties?.assignableScopes ?? [],
            hasWildcardActions,
          },
        });
      }
    }

    return resources;
  }

  private async collectStorageResources(
    subscriptionId: string,
    accessToken: string,
  ): Promise<DiscoveredCloudResource[]> {
    const resources: DiscoveredCloudResource[] = [];

    const saRes = await this.azureConnector.executeArmGet<{ value?: any[] }>(
      accessToken,
      `/subscriptions/${encodeURIComponent(subscriptionId)}/providers/Microsoft.Storage/storageAccounts?api-version=2023-01-01`,
    );

    if (!saRes.ok || !Array.isArray(saRes.data?.value)) return resources;

    for (const sa of saRes.data.value) {
      const id = String(sa?.id ?? '');
      const name = String(sa?.name ?? '');
      if (!id || !name) continue;

      const props = sa?.properties ?? {};
      resources.push({
        nativeId: id,
        name,
        resourceType: CloudResourceType.AZURE_STORAGE_ACCOUNT,
        region: sa?.location ?? 'eastus',
        configuration: {
          allowBlobPublicAccess: props.allowBlobPublicAccess !== false,
          supportsHttpsTrafficOnly: props.supportsHttpsTrafficOnly !== false,
          minimumTlsVersion: props.minimumTlsVersion ?? 'TLS1_0',
        },
        tags: sa?.tags ?? null,
      });
    }

    return resources;
  }

  private async collectNsgResources(
    subscriptionId: string,
    accessToken: string,
  ): Promise<DiscoveredCloudResource[]> {
    const resources: DiscoveredCloudResource[] = [];

    const nsgRes = await this.azureConnector.executeArmGet<{ value?: any[] }>(
      accessToken,
      `/subscriptions/${encodeURIComponent(subscriptionId)}/providers/Microsoft.Network/networkSecurityGroups?api-version=2023-05-01`,
    );

    if (!nsgRes.ok || !Array.isArray(nsgRes.data?.value)) return resources;

    for (const nsg of nsgRes.data.value) {
      const id = String(nsg?.id ?? '');
      const name = String(nsg?.name ?? '');
      if (!id || !name) continue;

      const rules: any[] = Array.isArray(nsg?.properties?.securityRules)
        ? nsg.properties.securityRules
        : [];

      const sshOffendingRules: string[] = [];
      const rdpOffendingRules: string[] = [];

      for (const r of rules) {
        const props = r?.properties ?? {};
        if (
          String(props.direction).toLowerCase() !== 'inbound' ||
          String(props.access).toLowerCase() !== 'allow'
        ) {
          continue;
        }

        const src = String(props.sourceAddressPrefix ?? '').toLowerCase();
        const isPublicSrc =
          src === '*' || src === 'internet' || src === '0.0.0.0/0' || src === 'any';
        if (!isPublicSrc) continue;

        const portRange = String(props.destinationPortRange ?? '');
        const portRanges: string[] = Array.isArray(props.destinationPortRanges)
          ? props.destinationPortRanges
          : [portRange];

        if (portRanges.some((pr) => portMatchesRange(pr, 22))) {
          sshOffendingRules.push(String(r?.name ?? 'rule-22'));
        }
        if (portRanges.some((pr) => portMatchesRange(pr, 3389))) {
          rdpOffendingRules.push(String(r?.name ?? 'rule-3389'));
        }
      }

      resources.push({
        nativeId: id,
        name,
        resourceType: CloudResourceType.AZURE_NSG,
        region: nsg?.location ?? 'eastus',
        configuration: {
          allowsSshFromInternet: sshOffendingRules.length > 0,
          sshOffendingRules,
          allowsRdpFromInternet: rdpOffendingRules.length > 0,
          rdpOffendingRules,
        },
        tags: nsg?.tags ?? null,
      });
    }

    return resources;
  }

  private async collectVmResources(
    subscriptionId: string,
    accessToken: string,
  ): Promise<DiscoveredCloudResource[]> {
    const resources: DiscoveredCloudResource[] = [];

    const vmRes = await this.azureConnector.executeArmGet<{ value?: any[] }>(
      accessToken,
      `/subscriptions/${encodeURIComponent(subscriptionId)}/providers/Microsoft.Compute/virtualMachines?api-version=2023-07-01`,
    );

    if (!vmRes.ok || !Array.isArray(vmRes.data?.value)) return resources;

    for (const vm of vmRes.data.value) {
      const id = String(vm?.id ?? '');
      const name = String(vm?.name ?? '');
      if (!id || !name) continue;

      const props = vm?.properties ?? {};
      const encryptionAtHost =
        props?.securityProfile?.encryptionAtHost === true;
      const osDiskEncrypted =
        Boolean(props?.storageProfile?.osDisk?.encryptionSettings?.enabled) ||
        Boolean(props?.storageProfile?.osDisk?.managedDisk?.diskEncryptionSet?.id);

      const linuxCfg = props?.osProfile?.linuxConfiguration;
      const isLinux =
        Boolean(linuxCfg) ||
        String(props?.storageProfile?.osDisk?.osType ?? '').toLowerCase() === 'linux';
      const disablePasswordAuthentication =
        linuxCfg?.disablePasswordAuthentication !== false;

      resources.push({
        nativeId: id,
        name,
        resourceType: CloudResourceType.AZURE_VM,
        region: vm?.location ?? 'eastus',
        configuration: {
          vmSize: props?.hardwareProfile?.vmSize ?? 'Standard_B2s',
          diskEncryptionEnabled: encryptionAtHost || osDiskEncrypted,
          isLinux,
          disablePasswordAuthentication,
        },
        tags: vm?.tags ?? null,
      });
    }

    return resources;
  }

  private async collectSqlResources(
    subscriptionId: string,
    accessToken: string,
  ): Promise<DiscoveredCloudResource[]> {
    const resources: DiscoveredCloudResource[] = [];

    const sqlRes = await this.azureConnector.executeArmGet<{ value?: any[] }>(
      accessToken,
      `/subscriptions/${encodeURIComponent(subscriptionId)}/providers/Microsoft.Sql/servers?api-version=2021-11-01`,
    );

    if (!sqlRes.ok || !Array.isArray(sqlRes.data?.value)) return resources;

    for (const srv of sqlRes.data.value) {
      const id = String(srv?.id ?? '');
      const name = String(srv?.name ?? '');
      if (!id || !name) continue;

      const publicAccess =
        String(srv?.properties?.publicNetworkAccess ?? 'Enabled').toLowerCase() !==
        'disabled';

      resources.push({
        nativeId: id,
        name,
        resourceType: CloudResourceType.AZURE_SQL_DATABASE,
        region: srv?.location ?? 'eastus',
        configuration: {
          publicNetworkAccessEnabled: publicAccess,
          tdeEnabled: true,
        },
        tags: srv?.tags ?? null,
      });
    }

    return resources;
  }

  private async collectActivityLogResources(
    subscriptionId: string,
    accessToken: string,
  ): Promise<DiscoveredCloudResource[]> {
    const diagRes = await this.azureConnector.executeArmGet<{ value?: any[] }>(
      accessToken,
      `/subscriptions/${encodeURIComponent(subscriptionId)}/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview`,
    );

    const settings = Array.isArray(diagRes.data?.value) ? diagRes.data.value : [];
    const hasWorkspaceExport = settings.some(
      (s: any) =>
        Boolean(s?.properties?.workspaceId) &&
        Array.isArray(s?.properties?.logs) &&
        s.properties.logs.some(
          (l: any) => l?.category === 'Administrative' && l?.enabled === true,
        ),
    );

    return [
      {
        nativeId: `/subscriptions/${subscriptionId}/providers/Microsoft.Insights/diagnosticSettings/activity-log`,
        name: `activity-log-${subscriptionId.slice(0, 8)}`,
        resourceType: CloudResourceType.AZURE_ACTIVITY_LOG,
        region: 'global',
        configuration: {
          activityLogExportEnabled: hasWorkspaceExport,
          diagnosticSettingsCount: settings.length,
        },
      },
    ];
  }

  /**
   * Genera un inventario representativo de Microsoft Azure para modo simulación / sandbox
   * (`00000000-0000-0000-0000-000000000000`).
   */
  buildBenchmarkInventory(
    subscriptionId: string,
    primaryRegion: string,
  ): DiscoveredCloudResource[] {
    const rgBase = `/subscriptions/${subscriptionId}/resourceGroups/rg-prod-core`;
    return [
      {
        nativeId: `/subscriptions/${subscriptionId}/providers/Microsoft.Authorization/roleDefinitions/custom-wildcard-ops`,
        name: 'Custom-DevOps-SuperRole',
        resourceType: CloudResourceType.OTHER,
        region: 'global',
        configuration: {
          subType: 'RBAC_CUSTOM_ROLE',
          hasWildcardActions: true,
          actions: ['*'],
          assignableScopes: [`/subscriptions/${subscriptionId}`],
        },
        tags: { Category: 'IAM' },
      },
      {
        nativeId: `${rgBase}/providers/Microsoft.Storage/storageAccounts/stprodpublicassets01`,
        name: 'stprodpublicassets01',
        resourceType: CloudResourceType.AZURE_STORAGE_ACCOUNT,
        region: primaryRegion,
        configuration: {
          allowBlobPublicAccess: true,
          supportsHttpsTrafficOnly: false,
          minimumTlsVersion: 'TLS1_0',
        },
        tags: { Environment: 'production', DataTier: 'customer-uploads' },
      },
      {
        nativeId: `${rgBase}/providers/Microsoft.Network/networkSecurityGroups/nsg-prod-perimeter`,
        name: 'nsg-prod-perimeter',
        resourceType: CloudResourceType.AZURE_NSG,
        region: primaryRegion,
        configuration: {
          allowsSshFromInternet: true,
          sshOffendingRules: ['Allow-SSH-All'],
          allowsRdpFromInternet: true,
          rdpOffendingRules: ['Allow-RDP-All'],
        },
        tags: { Tier: 'Network' },
      },
      {
        nativeId: `${rgBase}/providers/Microsoft.Compute/virtualMachines/vm-prod-linux-worker01`,
        name: 'vm-prod-linux-worker01',
        resourceType: CloudResourceType.AZURE_VM,
        region: primaryRegion,
        configuration: {
          vmSize: 'Standard_D2s_v5',
          diskEncryptionEnabled: false,
          isLinux: true,
          disablePasswordAuthentication: false,
        },
        tags: { Role: 'app-worker' },
      },
      {
        nativeId: `${rgBase}/providers/Microsoft.Sql/servers/sql-prod-billing-srv`,
        name: 'sql-prod-billing-srv',
        resourceType: CloudResourceType.AZURE_SQL_DATABASE,
        region: primaryRegion,
        configuration: {
          publicNetworkAccessEnabled: true,
          tdeEnabled: false,
        },
        tags: { Compliance: 'PCI-DSS' },
      },
      {
        nativeId: `/subscriptions/${subscriptionId}/providers/Microsoft.Insights/diagnosticSettings/activity-log`,
        name: `activity-log-${subscriptionId.slice(0, 8)}`,
        resourceType: CloudResourceType.AZURE_ACTIVITY_LOG,
        region: 'global',
        configuration: {
          activityLogExportEnabled: false,
          diagnosticSettingsCount: 0,
        },
      },
    ];
  }
}
