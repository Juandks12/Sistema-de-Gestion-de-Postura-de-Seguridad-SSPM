import {
  BadRequestException,
  Injectable,
  Logger,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { FindingSeverity, FindingStatus, ScanSource, ScanType } from '@prisma/client';
import { PrismaService } from '../prisma/prisma.service';
import { ApiKeysService } from '../api-keys/api-keys.service';
import { RiskScoresService } from '../risk/risk-scores.service';
import { ScansService } from '../scans/scans.service';
import { ComplianceService } from '../compliance/compliance.service';
import { ComplianceFramework } from '../compliance/compliance.catalog';
import { RagRetrievalService } from '../ai/rag/rag-retrieval.service';
import { MCP_TOOLS_CATALOG, McpToolDefinition } from './mcp-tools.catalog';

export interface JsonRpcRequest {
  jsonrpc: '2.0';
  id?: string | number | null;
  method: string;
  params?: Record<string, unknown>;
}

export interface JsonRpcResponse {
  jsonrpc: '2.0';
  id: string | number | null;
  result?: unknown;
  error?: {
    code: number;
    message: string;
    data?: unknown;
  };
}

export interface McpCallResult {
  content: Array<{
    type: 'text';
    text: string;
  }>;
  isError?: boolean;
}

@Injectable()
export class McpServerService {
  private readonly logger = new Logger(McpServerService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly apiKeysService: ApiKeysService,
    private readonly riskScoresService: RiskScoresService,
    private readonly scansService: ScansService,
    private readonly complianceService: ComplianceService,
    private readonly ragRetrievalService: RagRetrievalService,
  ) {}

  /**
   * Obtiene el catálogo de herramientas expuestas según el estándar MCP.
   */
  getToolsCatalog(): McpToolDefinition[] {
    return MCP_TOOLS_CATALOG;
  }

  /**
   * Valida la clave de API del cliente MCP y resuelve la organización asociada.
   */
  async authenticateApiKey(rawKey: string): Promise<{ organizationId: string; keyId: string; scopes: string[] }> {
    const validated = await this.apiKeysService.validateApiKey(rawKey);
    if (!validated) {
      throw new UnauthorizedException('Clave de API de SSPM inválida, revocada o expirada.');
    }
    return {
      organizationId: validated.organizationId,
      keyId: validated.id,
      scopes: validated.scopes,
    };
  }

  /**
   * Procesa una solicitud JSON-RPC 2.0 bajo el protocolo MCP.
   */
  async handleJsonRpc(
    request: JsonRpcRequest,
    organizationId: string,
  ): Promise<JsonRpcResponse> {
    const id = request.id ?? null;

    try {
      switch (request.method) {
        case 'initialize':
          return {
            jsonrpc: '2.0',
            id,
            result: {
              protocolVersion: '2024-11-05',
              capabilities: {
                tools: {
                  listChanged: false,
                },
              },
              serverInfo: {
                name: 'SecAudit AI SSPM Native MCP Server',
                version: '1.0.0',
              },
            },
          };

        case 'notifications/initialized':
          return {
            jsonrpc: '2.0',
            id,
            result: {},
          };

        case 'ping':
          return {
            jsonrpc: '2.0',
            id,
            result: {},
          };

        case 'tools/list':
          return {
            jsonrpc: '2.0',
            id,
            result: {
              tools: this.getToolsCatalog(),
            },
          };

        case 'tools/call': {
          const params = request.params as { name?: string; arguments?: Record<string, unknown> } | undefined;
          if (!params?.name) {
            return {
              jsonrpc: '2.0',
              id,
              error: { code: -32602, message: 'Parámetro "name" de herramienta requerido en tools/call' },
            };
          }

          const callResult = await this.executeTool(params.name, params.arguments || {}, organizationId);
          return {
            jsonrpc: '2.0',
            id,
            result: callResult,
          };
        }

        default:
          return {
            jsonrpc: '2.0',
            id,
            error: {
              code: -32601,
              message: `Método MCP no soportado: ${request.method}`,
            },
          };
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      this.logger.error(`Error procesando solicitud MCP [${request.method}]: ${msg}`);
      return {
        jsonrpc: '2.0',
        id,
        error: {
          code: -32000,
          message: msg,
        },
      };
    }
  }

  /**
   * Ejecuta la herramienta de seguridad solicitada dentro del contexto del tenant.
   */
  async executeTool(
    name: string,
    args: Record<string, unknown>,
    organizationId: string,
  ): Promise<McpCallResult> {
    switch (name) {
      case 'sspm_get_posture':
        return this.toolGetPosture(organizationId, args.assetId as string | undefined);

      case 'sspm_list_critical_findings':
        return this.toolListCriticalFindings(organizationId, args);

      case 'sspm_trigger_scan':
        return this.toolTriggerScan(organizationId, args);

      case 'sspm_query_compliance_gap':
        return this.toolQueryComplianceGap(organizationId, args.framework as string);

      case 'sspm_get_hardening_guide':
        return this.toolGetHardeningGuide(args.query as string, args.limit as number | undefined);

      default:
        return {
          content: [
            {
              type: 'text',
              text: `Herramienta desconocida: '${name}'. Consulta tools/list para ver el catálogo disponible.`,
            },
          ],
          isError: true,
        };
    }
  }

  private async toolGetPosture(organizationId: string, assetId?: string): Promise<McpCallResult> {
    const current = await this.riskScoresService.current(organizationId, assetId);
    const assetCount = await this.prisma.asset.count({
      where: { organizationId, isActive: true },
    });

    const openFindingsCount = await this.prisma.finding.count({
      where: { organizationId, status: FindingStatus.OPEN },
    });

    const counts = current.counts;
    const text = `# Postura de Seguridad SSPM (${assetId ? `Activo: ${assetId}` : 'Nivel Organizacional'})
- **Security Score**: ${current.score ?? 'Sin auditar'}/100 (Grado: **${current.grade ?? 'N/A'}**)
- **Activos Totales Activos**: ${assetCount}
- **Total Hallazgos Abiertos**: ${openFindingsCount}

### Desglose por Severidad de Hallazgos Abiertos:
- 🔴 **Críticos**: ${counts.CRITICAL}
- 🟠 **Altos**: ${counts.HIGH}
- 🟡 **Medios**: ${counts.MEDIUM}
- 🔵 **Bajos**: ${counts.LOW}
- ⚪ **Informativos**: ${counts.INFO}

*Estado del modelo*: ${current.score && current.score >= 80 ? 'Postura Saludable' : 'Requiere Remediación Inmediata'}.`;

    return { content: [{ type: 'text', text }] };
  }

  private async toolListCriticalFindings(
    organizationId: string,
    args: Record<string, unknown>,
  ): Promise<McpCallResult> {
    const limit = Math.min(Math.max(Number(args.limit) || 10, 1), 50);
    const severityFilter = (args.severity as string) || 'ALL';
    const assetId = args.assetId as string | undefined;

    let severities: FindingSeverity[] = [FindingSeverity.CRITICAL, FindingSeverity.HIGH];
    if (severityFilter === 'CRITICAL') severities = [FindingSeverity.CRITICAL];
    if (severityFilter === 'HIGH') severities = [FindingSeverity.HIGH];

    const findings = await this.prisma.finding.findMany({
      where: {
        organizationId,
        status: FindingStatus.OPEN,
        severity: { in: severities },
        ...(assetId ? { assetId } : {}),
      },
      include: {
        asset: { select: { value: true, type: true } },
      },
      orderBy: [{ severity: 'asc' }, { cvssScore: 'desc' }],
      take: limit,
    });

    if (findings.length === 0) {
      return {
        content: [
          {
            type: 'text',
            text: `No se encontraron hallazgos abiertos con severidad ${severityFilter} en la organización. ¡Excelente postura!`,
          },
        ],
      };
    }

    let report = `# Hallazgos Críticos y Altos Detectados (${findings.length} listados de máx ${limit})\n\n`;
    for (const f of findings) {
      report += `### [${f.severity}] ${f.title}\n`;
      report += `- **ID**: \`${f.id}\` | **Regla**: \`${f.ruleId}\`\n`;
      report += `- **Activo**: ${f.asset?.value || 'N/A'} (${f.asset?.type || 'N/A'})\n`;
      report += `- **Ubicación**: \`${f.location}\`\n`;
      report += `- **CVSS**: ${f.cvssScore ?? 'N/A'}\n`;
      report += `- **Descripción**: ${f.description}\n`;
      report += `- **Recomendación**: ${f.recommendation}\n\n`;
    }

    return { content: [{ type: 'text', text: report.trim() }] };
  }

  private async toolTriggerScan(
    organizationId: string,
    args: Record<string, unknown>,
  ): Promise<McpCallResult> {
    const assetId = args.assetId as string;
    const scanType = args.scanType as ScanType;

    if (!assetId || !scanType) {
      return {
        content: [{ type: 'text', text: 'Error: assetId y scanType son obligatorios para lanzar un escaneo.' }],
        isError: true,
      };
    }

    try {
      const scan = await this.scansService.enqueue({
        organizationId,
        assetId,
        type: scanType,
        requestedById: null,
        source: ScanSource.MANUAL,
      });

      return {
        content: [
          {
            type: 'text',
            text: `Escaneo ${scanType} encolado exitosamente.\n- **Scan ID**: \`${scan.id}\`\n- **Estado**: \`${scan.status}\`\n- **Activo**: \`${scan.asset?.value || assetId}\`\n- **Fecha Inicio**: ${scan.createdAt.toISOString()}`,
          },
        ],
      };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      return {
        content: [{ type: 'text', text: `No se pudo encolar el escaneo: ${msg}` }],
        isError: true,
      };
    }
  }

  private async toolQueryComplianceGap(
    organizationId: string,
    frameworkArg?: string,
  ): Promise<McpCallResult> {
    if (!frameworkArg) {
      return {
        content: [{ type: 'text', text: 'Error: el parámetro framework es obligatorio.' }],
        isError: true,
      };
    }

    const framework = frameworkArg as ComplianceFramework;
    if (!Object.values(ComplianceFramework).includes(framework)) {
      return {
        content: [
          {
            type: 'text',
            text: `Marco '${frameworkArg}' no reconocido. Opciones válidas: ${Object.values(ComplianceFramework).join(', ')}`,
          },
        ],
        isError: true,
      };
    }

    try {
      const evaluation = await this.complianceService.getFrameworkDetails(organizationId, framework);

      let text = `# Evaluación de Cumplimiento: ${evaluation.metadata.name} (${evaluation.metadata.version})\n`;
      text += `- **Porcentaje de Cumplimiento**: **${evaluation.summary.compliancePercentage}%**\n`;
      text += `- **Controles Aprobados**: ${evaluation.summary.passedControls}/${evaluation.summary.totalControls}\n`;
      text += `- **Controles con Brechas**: ${evaluation.summary.failedControls}\n\n`;

      if (evaluation.summary.failedControls > 0) {
        text += `### Brechas de Cumplimiento Detectadas:\n`;
        for (const c of evaluation.controls.filter((ctrl) => ctrl.status === 'NON_COMPLIANT')) {
          text += `#### ❌ [${c.control.code}] ${c.control.title}\n`;
          text += `- **Dominio**: ${c.control.domain}\n`;
          text += `- **Descripción**: ${c.control.description}\n`;
          text += `- **Hallazgos Asociados**: ${c.failingFindingsCount} (Peor severidad: ${c.worstSeverity || 'N/A'})\n\n`;
        }
      } else {
        text += `🎉 Todos los controles del marco se encuentran en estado COMPLIANT en el perímetro auditado.`;
      }

      return { content: [{ type: 'text', text: text.trim() }] };
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      return {
        content: [{ type: 'text', text: `Error consultando cumplimiento normativo: ${msg}` }],
        isError: true,
      };
    }
  }

  private async toolGetHardeningGuide(query?: string, limit = 3): Promise<McpCallResult> {
    if (!query) {
      return {
        content: [{ type: 'text', text: 'Error: el parámetro "query" es requerido.' }],
        isError: true,
      };
    }

    const results = await this.ragRetrievalService.searchSemantic({
      query,
      limit: Math.min(Math.max(limit, 1), 6),
      minSimilarity: 0.05,
    });

    if (results.length === 0) {
      return {
        content: [
          {
            type: 'text',
            text: `No se encontraron directrices ni snippets específicos para '${query}' en la base de conocimiento vectorial.`,
          },
        ],
      };
    }

    let text = `# Guías y Snippets de Bastionado Recuperados (RAG pgvector)\n\n`;
    for (const r of results) {
      text += `### ${r.title} [${r.category}] (Similitud: ${(r.similarity * 100).toFixed(1)}%)\n`;
      text += `${r.content}\n\n`;
      text += `---\n\n`;
    }

    return { content: [{ type: 'text', text: text.trim() }] };
  }
}
