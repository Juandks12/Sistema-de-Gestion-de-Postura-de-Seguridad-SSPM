import { Injectable, Logger } from '@nestjs/common';
import {
  AzureBoardsCredentials,
  CreatedTicketResult,
  TestConnectionResult,
  TicketingFindingPayload,
  TicketingProvider,
  TicketStatusResult,
} from './ticketing.types';

@Injectable()
export class AzureBoardsConnectorService {
  private readonly logger = new Logger(AzureBoardsConnectorService.name);

  private buildAuthHeader(credentials: AzureBoardsCredentials): string {
    const token = Buffer.from(`:${credentials.personalAccessToken.trim()}`).toString('base64');
    return `Basic ${token}`;
  }

  private normalizeUrl(url: string): string {
    return url.trim().replace(/\/+$/, '');
  }

  /**
   * Valida conectividad y permisos con Azure DevOps Boards REST API v7.1.
   */
  async testConnection(
    instanceUrl: string,
    project: string,
    credentials: AzureBoardsCredentials,
  ): Promise<TestConnectionResult> {
    const base = this.normalizeUrl(instanceUrl);
    const auth = this.buildAuthHeader(credentials);
    const cleanProject = project.trim();

    try {
      const url = `${base}/${encodeURIComponent(cleanProject)}/_apis/wit/workitemtypes?api-version=7.1`;
      const res = await fetch(url, {
        headers: { Authorization: auth, Accept: 'application/json' },
      });

      if (!res.ok) {
        const errorText = await res.text();
        return {
          ok: false,
          provider: TicketingProvider.AZURE_BOARDS,
          error: `Error al conectar con Azure DevOps (HTTP ${res.status}): ${errorText.slice(0, 250)}`,
          availableIssueTypes: [],
        };
      }

      const data = (await res.json()) as { value?: Array<{ name: string; isDisabled?: boolean }> };
      const issueTypes = (data.value ?? [])
        .filter((t) => !t.isDisabled)
        .map((t) => t.name);

      return {
        ok: true,
        provider: TicketingProvider.AZURE_BOARDS,
        projectName: cleanProject,
        availableIssueTypes: issueTypes.length > 0 ? issueTypes : ['Issue', 'Bug', 'Task'],
      };
    } catch (err) {
      this.logger.error(`Fallo conectando a Azure DevOps: ${(err as Error).message}`);
      return {
        ok: false,
        provider: TicketingProvider.AZURE_BOARDS,
        error: `No se pudo conectar a Azure DevOps: ${(err as Error).message}`,
        availableIssueTypes: [],
      };
    }
  }

  /**
   * Crea un Work Item en Azure DevOps Boards utilizando JSON Patch v7.1.
   */
  async createWorkItem(
    instanceUrl: string,
    project: string,
    workItemType: string,
    credentials: AzureBoardsCredentials,
    payload: TicketingFindingPayload,
  ): Promise<CreatedTicketResult> {
    const base = this.normalizeUrl(instanceUrl);
    const auth = this.buildAuthHeader(credentials);
    const cleanProject = project.trim();
    const cleanType = workItemType.trim();

    // Mapeo de prioridad en Azure Boards (1=Crítico a 4=Bajo)
    const priorityMap: Record<string, number> = {
      CRITICAL: 1,
      HIGH: 2,
      MEDIUM: 3,
      LOW: 4,
      INFO: 4,
    };
    const priorityNum = priorityMap[payload.severity] ?? 3;

    const htmlDescription = this.buildHtmlDescription(payload);
    const tags = `SecAudit; SSPM; ${payload.severity}; ${payload.ruleId}`;

    const patchDoc = [
      {
        op: 'add',
        path: '/fields/System.Title',
        value: `[SecAudit] [${payload.severity}] ${payload.title} (${payload.assetValue})`,
      },
      {
        op: 'add',
        path: '/fields/System.Description',
        value: htmlDescription,
      },
      {
        op: 'add',
        path: '/fields/Microsoft.VSTS.Common.Priority',
        value: priorityNum,
      },
      {
        op: 'add',
        path: '/fields/System.Tags',
        value: tags,
      },
    ];

    const url = `${base}/${encodeURIComponent(cleanProject)}/_apis/wit/workitems/$${encodeURIComponent(cleanType)}?api-version=7.1`;
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        Authorization: auth,
        'Content-Type': 'application/json-patch+json',
        Accept: 'application/json',
      },
      body: JSON.stringify(patchDoc),
    });

    if (!res.ok) {
      const errText = await res.text();
      throw new Error(`Azure DevOps respondió HTTP ${res.status}: ${errText.slice(0, 300)}`);
    }

    const data = (await res.json()) as {
      id: number;
      fields: Record<string, unknown>;
      _links?: { html?: { href?: string } };
    };

    const workItemId = String(data.id);
    const htmlUrl = data._links?.html?.href || `${base}/${encodeURIComponent(cleanProject)}/_workitems/edit/${workItemId}`;
    const state = typeof data.fields?.['System.State'] === 'string' ? data.fields['System.State'] : 'To Do';

    return {
      key: workItemId,
      url: htmlUrl,
      status: state,
    };
  }

  /**
   * Consulta el estado actual de un Work Item en Azure DevOps.
   */
  async getWorkItemStatus(
    instanceUrl: string,
    credentials: AzureBoardsCredentials,
    workItemId: string,
  ): Promise<TicketStatusResult> {
    const base = this.normalizeUrl(instanceUrl);
    const auth = this.buildAuthHeader(credentials);

    const url = `${base}/_apis/wit/workitems/${encodeURIComponent(workItemId)}?api-version=7.1`;
    const res = await fetch(url, {
      headers: { Authorization: auth, Accept: 'application/json' },
    });

    if (!res.ok) {
      throw new Error(`No se pudo consultar el Work Item #${workItemId} en Azure DevOps (HTTP ${res.status})`);
    }

    const data = (await res.json()) as {
      id: number;
      fields: {
        'System.State'?: string;
        'System.AssignedTo'?: { displayName?: string };
        'System.ChangedDate'?: string;
      };
    };

    const state = data.fields?.['System.State'] ?? 'Desconocido';
    const isClosed = /resolved|closed|done|completed|cerrado|resuelto/i.test(state);

    return {
      key: String(data.id),
      status: state,
      isClosed,
      assignee: data.fields?.['System.AssignedTo']?.displayName ?? null,
      updatedAt: data.fields?.['System.ChangedDate'] ? new Date(data.fields['System.ChangedDate']) : undefined,
    };
  }

  /**
   * Construye una descripción estructurada en HTML compatible con Azure DevOps.
   */
  private buildHtmlDescription(payload: TicketingFindingPayload): string {
    const sections: string[] = [
      `<h3>Resumen Ejecutivo del Hallazgo de Seguridad</h3>`,
      `<p><strong>Activo Afectado:</strong> ${escapeHtml(payload.assetValue)} | <strong>Ubicación:</strong> <code>${escapeHtml(payload.location)}</code></p>`,
      `<p><strong>Severidad:</strong> <b>${payload.severity}</b> (CVSS: ${payload.cvssScore ?? 'N/A'}) | <strong>Regla:</strong> <code>${escapeHtml(payload.ruleId)}</code></p>`,
      `<p>${escapeHtml(payload.description)}</p>`,
      `<h4>Pasos de Remediación y Endurecimiento</h4>`,
      `<p>${escapeHtml(payload.recommendation)}</p>`,
    ];

    if (payload.cweId || payload.owaspCategory || payload.mitreAttackTechnique) {
      sections.push(`<h4>Taxonomía y Vectores de Ciberseguridad</h4><ul>`);
      if (payload.cweId) sections.push(`<li><b>CWE:</b> ${escapeHtml(payload.cweId)}</li>`);
      if (payload.owaspCategory) sections.push(`<li><b>OWASP:</b> ${escapeHtml(payload.owaspCategory)}</li>`);
      if (payload.mitreAttackTechnique) sections.push(`<li><b>MITRE ATT&CK:</b> ${escapeHtml(payload.mitreAttackTechnique)}</li>`);
      sections.push(`</ul>`);
    }

    if (payload.complianceControls && payload.complianceControls.length > 0) {
      sections.push(`<h4>Controles Normativos GRC Impactados</h4><ul>`);
      for (const ctrl of payload.complianceControls) {
        sections.push(`<li>[${escapeHtml(ctrl.frameworkName)}] <b>${escapeHtml(ctrl.code)}</b>: ${escapeHtml(ctrl.title)}</li>`);
      }
      sections.push(`</ul>`);
    }

    if (payload.customNotes) {
      sections.push(`<h4>Notas del Analista</h4><p>${escapeHtml(payload.customNotes)}</p>`);
    }

    return sections.join('\n');
  }
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
