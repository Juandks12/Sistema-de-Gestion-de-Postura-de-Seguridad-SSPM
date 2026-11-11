import { CloudProvider, CloudResourceType } from '@prisma/client';
import { GcpConnectorService } from '../connectors/gcp-connector.service';
import { GcpCspmEvaluatorService } from './gcp-cspm.evaluator';
import { DiscoveredCloudResource } from './cspm-evaluator.types';

describe('GcpCspmEvaluatorService', () => {
  let evaluator: GcpCspmEvaluatorService;
  let gcpConnectorMock: {
    acquireAccessToken: jest.Mock;
    executeGcpGet: jest.Mock;
  };

  beforeEach(() => {
    gcpConnectorMock = {
      acquireAccessToken: jest.fn(),
      executeGcpGet: jest.fn(),
    };
    evaluator = new GcpCspmEvaluatorService(
      gcpConnectorMock as unknown as GcpConnectorService,
    );
  });

  it('evalúa las 5 reglas CSPM de GCP cuando los recursos presentan configuraciones riesgosas', () => {
    const projectId = 'sec-audit-gcp-test-01';
    const resources = evaluator.buildBenchmarkInventory(projectId, 'us-central1');

    const findings = evaluator.evaluateInventoryRules(projectId, resources);
    const detectedRuleIds = new Set(findings.map((f) => f.ruleId));

    expect(detectedRuleIds).toEqual(
      new Set([
        'GCP-STORAGE-PUBLIC-BUCKET',
        'GCP-IAM-KEY-ROTATION',
        'GCP-COMPUTE-PUBLIC-IP',
        'GCP-SQL-PUBLIC-ACCESS',
        'GCP-LOGGING-SINKS-OFF',
      ]),
    );
  });

  it('no genera hallazgos cuando los recursos de GCP cumplen las líneas base seguras', () => {
    const projectId = 'sec-audit-gcp-hardened';
    const hardenedResources: DiscoveredCloudResource[] = [
      {
        nativeId: `projects/_/buckets/${projectId}-vault`,
        name: `${projectId}-vault`,
        resourceType: CloudResourceType.GCP_STORAGE_BUCKET,
        region: 'us-central1',
        configuration: {
          uniformBucketLevelAccess: true,
          publicAccessPrevention: 'enforced',
          isPublic: false,
          publicMembers: [],
        },
      },
      {
        nativeId: `projects/${projectId}/serviceAccounts/auditor@${projectId}.iam.gserviceaccount.com`,
        name: `auditor@${projectId}.iam.gserviceaccount.com`,
        resourceType: CloudResourceType.GCP_SERVICE_ACCOUNT,
        region: 'global',
        configuration: {
          keys: [{ keyId: 'key-fresh', ageDays: 20 }],
        },
      },
      {
        nativeId: `projects/${projectId}/zones/us-central1-a/instances/worker-01`,
        name: 'worker-01',
        resourceType: CloudResourceType.GCP_COMPUTE_INSTANCE,
        region: 'us-central1',
        configuration: {
          hasPublicIp: false,
          exposedPorts: [],
        },
      },
      {
        nativeId: `projects/${projectId}/instances/db-secure`,
        name: 'db-secure',
        resourceType: CloudResourceType.GCP_SQL_INSTANCE,
        region: 'us-central1',
        configuration: {
          authorizedNetworks: ['10.128.0.0/16'],
          requireSsl: true,
          ipv4Enabled: false,
        },
      },
      {
        nativeId: `projects/${projectId}/sinks/export-sink`,
        name: 'export-sink',
        resourceType: CloudResourceType.GCP_LOGGING_SINK,
        region: 'global',
        configuration: {
          hasCentralizedExportSink: true,
        },
      },
    ];

    const findings = evaluator.evaluateInventoryRules(projectId, hardenedResources);
    expect(findings).toHaveLength(0);
  });

  it('debe ejecutar evaluateProject en modo simulado/sandbox retornando inventario y hallazgos', async () => {
    const result = await evaluator.evaluateProject({
      authInput: {
        projectId: 'sandbox-gcp-project',
        clientEmail: 'sa@test.com',
        privateKey: 'key',
      },
      monitoredRegions: ['us-central1'],
      simulate: true,
    });

    expect(result.provider).toBe(CloudProvider.GCP);
    expect(result.accountOrSubscriptionId).toBe('sandbox-gcp-project');
    expect(result.simulated).toBe(true);
    expect(result.evaluatedRulesCount).toBe(5);
    expect(result.resources.length).toBeGreaterThanOrEqual(5);
    expect(result.findings.length).toBe(5);
  });

  it('debe consultar APIs REST de GCP en vivo cuando no es sandbox', async () => {
    gcpConnectorMock.acquireAccessToken.mockResolvedValueOnce({
      accessToken: 'test-oauth-token',
      expiresIn: 3600,
    });

    gcpConnectorMock.executeGcpGet.mockResolvedValueOnce({
      ok: true,
      status: 200,
      data: {
        items: [
          {
            name: 'my-production-bucket',
            location: 'US',
            iamConfiguration: {
              uniformBucketLevelAccess: { enabled: false },
            },
          },
        ],
      },
    });

    const result = await evaluator.evaluateProject({
      authInput: {
        projectId: 'live-enterprise-project',
        clientEmail: 'sspm@live-enterprise-project.iam.gserviceaccount.com',
        privateKey: 'dummy-pem',
      },
      monitoredRegions: ['us-central1'],
      simulate: false,
    });

    expect(result.provider).toBe(CloudProvider.GCP);
    expect(result.simulated).toBe(false);
    expect(gcpConnectorMock.acquireAccessToken).toHaveBeenCalledTimes(1);
    expect(gcpConnectorMock.executeGcpGet).toHaveBeenCalled();
  });
});
