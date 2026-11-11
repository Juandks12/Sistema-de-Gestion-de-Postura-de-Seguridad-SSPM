import { UnauthorizedException } from '@nestjs/common';
import { FindingSeverity, FindingStatus, ScanSource, ScanType } from '@prisma/client';
import { PrismaService } from '../prisma/prisma.service';
import { ApiKeysService } from '../api-keys/api-keys.service';
import { RiskScoresService } from '../risk/risk-scores.service';
import { ScansService } from '../scans/scans.service';
import { ComplianceService } from '../compliance/compliance.service';
import { RagRetrievalService } from '../ai/rag/rag-retrieval.service';
import { McpServerService } from './mcp-server.service';
import { ComplianceFramework } from '../compliance/compliance.catalog';

describe('McpServerService', () => {
  let service: McpServerService;
  let prisma: {
    asset: { count: jest.Mock };
    finding: { count: jest.Mock; findMany: jest.Mock };
  };
  let apiKeysService: { validateApiKey: jest.Mock };
  let riskScoresService: { current: jest.Mock };
  let scansService: { enqueue: jest.Mock };
  let complianceService: { getFrameworkDetails: jest.Mock };
  let ragRetrievalService: { searchSemantic: jest.Mock };

  beforeEach(() => {
    prisma = {
      asset: { count: jest.fn().mockResolvedValue(12) },
      finding: { count: jest.fn().mockResolvedValue(4), findMany: jest.fn().mockResolvedValue([]) },
    };

    apiKeysService = {
      validateApiKey: jest.fn(),
    };

    riskScoresService = {
      current: jest.fn().mockResolvedValue({
        score: 85,
        grade: 'B',
        counts: { CRITICAL: 0, HIGH: 2, MEDIUM: 2, LOW: 0, INFO: 0 },
      }),
    };

    scansService = {
      enqueue: jest.fn(),
    };

    complianceService = {
      getFrameworkDetails: jest.fn(),
    };

    ragRetrievalService = {
      searchSemantic: jest.fn(),
    };

    service = new McpServerService(
      prisma as unknown as PrismaService,
      apiKeysService as unknown as ApiKeysService,
      riskScoresService as unknown as RiskScoresService,
      scansService as unknown as ScansService,
      complianceService as unknown as ComplianceService,
      ragRetrievalService as unknown as RagRetrievalService,
    );
  });

  it('debe exponer el catálogo completo de 5 herramientas MCP nativas', () => {
    const tools = service.getToolsCatalog();
    expect(tools).toHaveLength(5);
    const names = tools.map((t) => t.name);
    expect(names).toContain('sspm_get_posture');
    expect(names).toContain('sspm_list_critical_findings');
    expect(names).toContain('sspm_trigger_scan');
    expect(names).toContain('sspm_query_compliance_gap');
    expect(names).toContain('sspm_get_hardening_guide');
  });

  it('debe autenticar llaves de API válidas y rechazar inválidas', async () => {
    apiKeysService.validateApiKey.mockResolvedValueOnce({
      id: 'key-1',
      organizationId: 'org-1',
      name: 'Cursor MCP Key',
      scopes: ['mcp:tools'],
    });

    const auth = await service.authenticateApiKey('sspm_live_valid');
    expect(auth.organizationId).toBe('org-1');

    apiKeysService.validateApiKey.mockResolvedValueOnce(null);
    await expect(service.authenticateApiKey('sspm_live_invalid')).rejects.toThrow(
      UnauthorizedException,
    );
  });

  it('debe responder a initialize según especificación MCP 2024-11-05', async () => {
    const res = await service.handleJsonRpc(
      { jsonrpc: '2.0', id: 1, method: 'initialize' },
      'org-1',
    );
    expect(res.jsonrpc).toBe('2.0');
    expect(res.id).toBe(1);
    const result = res.result as { protocolVersion: string; serverInfo: { name: string } };
    expect(result.protocolVersion).toBe('2024-11-05');
    expect(result.serverInfo.name).toContain('SSPM');
  });

  it('debe responder a tools/list con las herramientas registradas', async () => {
    const res = await service.handleJsonRpc(
      { jsonrpc: '2.0', id: 2, method: 'tools/list' },
      'org-1',
    );
    expect(res.jsonrpc).toBe('2.0');
    const result = res.result as { tools: Array<{ name: string }> };
    expect(result.tools).toHaveLength(5);
  });

  it('debe ejecutar sspm_get_posture retornando el Security Score y hallazgos', async () => {
    const res = await service.executeTool('sspm_get_posture', {}, 'org-1');
    expect(res.content[0].text).toContain('Security Score');
    expect(res.content[0].text).toContain('85/100');
    expect(res.content[0].text).toContain('Activos Totales Activos**: 12');
  });

  it('debe ejecutar sspm_trigger_scan encolando el escaneo en ScansService', async () => {
    scansService.enqueue.mockResolvedValueOnce({
      id: 'scan-1',
      status: 'QUEUED',
      createdAt: new Date(),
      asset: { value: 'usco.edu.co' },
    });

    const res = await service.executeTool(
      'sspm_trigger_scan',
      { assetId: 'asset-1', scanType: 'WEB_HEADERS' },
      'org-1',
    );

    expect(scansService.enqueue).toHaveBeenCalledWith({
      organizationId: 'org-1',
      assetId: 'asset-1',
      type: 'WEB_HEADERS',
      requestedById: null,
      source: ScanSource.MANUAL,
    });
    expect(res.content[0].text).toContain('Escaneo WEB_HEADERS encolado exitosamente');
  });

  it('debe ejecutar sspm_query_compliance_gap retornando brechas del marco normativo', async () => {
    complianceService.getFrameworkDetails.mockResolvedValueOnce({
      metadata: { name: 'ISO/IEC 27001:2022', version: '2022' },
      summary: { compliancePercentage: 92, passedControls: 23, totalControls: 25, failedControls: 2 },
      controls: [
        {
          status: 'NON_COMPLIANT',
          control: { code: 'A.8.20', title: 'Seguridad de Redes', domain: 'Tecnológico', description: 'Control de redes' },
          failingFindingsCount: 1,
          worstSeverity: 'HIGH',
        },
      ],
    });

    const res = await service.executeTool(
      'sspm_query_compliance_gap',
      { framework: ComplianceFramework.ISO_27001 },
      'org-1',
    );

    expect(res.content[0].text).toContain('ISO/IEC 27001:2022');
    expect(res.content[0].text).toContain('Porcentaje de Cumplimiento**: **92%**');
    expect(res.content[0].text).toContain('A.8.20');
  });

  it('debe ejecutar sspm_get_hardening_guide recuperando snippets RAG', async () => {
    ragRetrievalService.searchSemantic.mockResolvedValueOnce([
      {
        id: 'guide-1',
        category: 'HARDENING_GUIDE',
        title: 'Bastionado de Strict-Transport-Security',
        content: 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;',
        similarity: 0.94,
      },
    ]);

    const res = await service.executeTool(
      'sspm_get_hardening_guide',
      { query: 'HSTS bastionado' },
      'org-1',
    );

    expect(res.content[0].text).toContain('Bastionado de Strict-Transport-Security');
    expect(res.content[0].text).toContain('max-age=31536000');
  });
});
