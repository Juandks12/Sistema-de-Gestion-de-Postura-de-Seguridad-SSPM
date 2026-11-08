import { Injectable, Logger } from '@nestjs/common';
import {
  CreatedTicketResult,
  JiraCredentials,
  TestConnectionResult,
  TicketingFindingPayload,
  TicketingProvider,
  TicketStatusResult,
} from './ticketing.types';

@Injectable()
export class JiraConnectorService {
  private readonly logger = new Logger(JiraConnectorService.name);

  private buildAuthHeader(credentials: JiraCredentials): string {
    const token = Buffer.from(`${credentials.email.trim()}:${credentials.apiToken.trim()}`).toString('base64');
    return `Basic ${token}`;
  }

  private normalizeUrl(url: string): string {
    return url.trim().replace(/\/+$/, '');
  }

  /**
   * Valida conectividad, autenticación y existencia del proyecto en Jira Cloud (REST API v3).
   */
  async testConnection(
    instanceUrl: string,
    projectKey: string,
    credentials: JiraCredentials,
  ): Promise<TestConnectionResult> {
    const base = this.normalizeUrl(instanceUrl);
    const auth = this.buildAuthHeader(credentials);

    try {
      // 1. Validar usuario actual
      const myselfRes = await fetch(`${base}/rest/api/3/myself`, {
        headers: { Authorization: auth, Accept: 'application/json' },
      });

      if (!myselfRes.ok) {
        const errorText = await myselfRes.text();
        return {
          ok: false,
          provider: TicketingProvider.JIRA,
          error: `Error de autenticación en Jira (${myselfRes.status}): ${errorText.slice(0, 200)}`,
          availableIssueTypes: [],
        };
      }
      const myself = (await myselfRes.json()) as { displayName?: string; emailAddress?: string };

      // 2. Validar proyecto y consultar tipos de issue disponibles
      const projectRes = await fetch(`${base}/rest/api/3/project/${encodeURIComponent(projectKey.trim())}`, {
        headers: { Authorization: auth, Accept: 'application/json' },
      });

      if (!projectRes.ok) {
        return {
          ok: false,
          provider: TicketingProvider.JIRA,
          accountName: myself.displayName || myself.emailAddress,
          error: `El proyecto "${projectKey}" no existe o el usuario no tiene permisos en Jira (HTTP ${projectRes.status}).`,
          availableIssueTypes: [],
        };
      }

      const project = (await projectRes.json()) as {
        name?: string;
        issueTypes?: Array<{ name: string; subtask: boolean }>;
      };

      const issueTypes = (project.issueTypes ?? [])
        .filter((it) => !it.subtask)
        .map((it) => it.name);

      return {
        ok: true,
        provider: TicketingProvider.JIRA,
        accountName: myself.displayName || myself.emailAddress,
        projectName: project.name ?? projectKey,
        availableIssueTypes: issueTypes.length > 0 ? issueTypes : ['Bug', 'Task'],
      };
    } catch (err) {
      this.logger.error(`Fallo conectando a Jira: ${(err as Error).message}`);
      return {
        ok: false,
        provider: TicketingProvider.JIRA,
        error: `No se pudo conectar a Jira: ${(err as Error).message}`,
        availableIssueTypes: [],
      };
    }
  }

  /**
   * Crea un Issue en Jira Cloud REST API v3 con estructura completa de seguridad y GRC.
   */
  async createIssue(
    instanceUrl: string,
    projectKey: string,
    issueType: string,
    credentials: JiraCredentials,
    payload: TicketingFindingPayload,
  ): Promise<CreatedTicketResult> {
    const base = this.normalizeUrl(instanceUrl);
    const auth = this.buildAuthHeader(credentials);

    // Mapeo de severidad a prioridad estándar de Jira
    const priorityMap: Record<string, string> = {
      CRITICAL: 'Highest',
      HIGH: 'High',
      MEDIUM: 'Medium',
      LOW: 'Low',
      INFO: 'Lowest',
    };

    const priorityName = priorityMap[payload.severity] || 'Medium';

    // Generar descripción estructurada en Atlassian Document Format (ADF)
    const adfDescription = this.buildAdfDescription(payload);

    const body = {
      fields: {
        project: { key: projectKey.trim().toUpperCase() },
        summary: `[SecAudit] [${payload.severity}] ${payload.title} (${payload.assetValue})`,
        issuetype: { name: issueType.trim() },
        priority: { name: priorityName },
        labels: [
          'sspm',
          'security',
          payload.severity.toLowerCase(),
          payload.ruleId.toLowerCase().replace(/[^a-z0-9_-]/g, '_'),
        ].slice(0, 10),
        description: adfDescription,
      },
    };

    const res = await fetch(`${base}/rest/api/3/issue`, {
      method: 'POST',
      headers: {
        Authorization: auth,
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify(body),
    });

    if (!res.ok) {
      const errText = await res.text();
      throw new Error(`Jira respondió error HTTP ${res.status}: ${errText.slice(0, 300)}`);
    }

    const data = (await res.json()) as { key: string; self: string };
    const issueKey = data.key;

    return {
      key: issueKey,
      url: `${base}/browse/${issueKey}`,
      status: 'Open',
    };
  }

  /**
   * Consulta el estado actual de un issue en Jira.
   */
  async getIssueStatus(
    instanceUrl: string,
    credentials: JiraCredentials,
    issueKey: string,
  ): Promise<TicketStatusResult> {
    const base = this.normalizeUrl(instanceUrl);
    const auth = this.buildAuthHeader(credentials);

    const res = await fetch(`${base}/rest/api/3/issue/${encodeURIComponent(issueKey)}?fields=status,assignee,updated`, {
      headers: { Authorization: auth, Accept: 'application/json' },
    });

    if (!res.ok) {
      throw new Error(`No se pudo consultar el issue ${issueKey} en Jira (HTTP ${res.status})`);
    }

    const data = (await res.json()) as {
      key: string;
      fields: {
        status?: { name: string; statusCategory?: { key: string } };
        assignee?: { displayName?: string };
        updated?: string;
      };
    };

    const statusName = data.fields?.status?.name ?? 'Desconocido';
    const categoryKey = data.fields?.status?.statusCategory?.key?.toLowerCase();
    const isClosed =
      categoryKey === 'done' ||
      /done|resolved|closed|resuelto|cerrado|finalizado/i.test(statusName);

    return {
      key: data.key,
      status: statusName,
      isClosed,
      assignee: data.fields?.assignee?.displayName ?? null,
      updatedAt: data.fields?.updated ? new Date(data.fields.updated) : undefined,
    };
  }

  /**
   * Construye un documento en Atlassian Document Format (ADF) para descripciones ricas en Jira v3.
   */
  private buildAdfDescription(payload: TicketingFindingPayload) {
    const content: unknown[] = [
      {
        type: 'heading',
        attrs: { level: 3 },
        content: [{ type: 'text', text: 'Resumen Ejecutivo del Hallazgo de Seguridad' }],
      },
      {
        type: 'paragraph',
        content: [
          { type: 'text', text: 'Activo Afectado: ', marks: [{ type: 'strong' }] },
          { type: 'text', text: payload.assetValue },
          { type: 'text', text: ' | Ubicación: ', marks: [{ type: 'strong' }] },
          { type: 'text', text: payload.location },
        ],
      },
      {
        type: 'paragraph',
        content: [
          { type: 'text', text: 'Severidad: ', marks: [{ type: 'strong' }] },
          { type: 'text', text: `${payload.severity} (CVSS: ${payload.cvssScore ?? 'N/A'})` },
          { type: 'text', text: ' | Regla: ', marks: [{ type: 'strong' }] },
          { type: 'text', text: payload.ruleId },
        ],
      },
      {
        type: 'paragraph',
        content: [{ type: 'text', text: payload.description }],
      },
      {
        type: 'heading',
        attrs: { level: 4 },
        content: [{ type: 'text', text: 'Pasos de Remediación y Endurecimiento Recomendados' }],
      },
      {
        type: 'paragraph',
        content: [{ type: 'text', text: payload.recommendation }],
      },
    ];

    if (payload.cweId || payload.owaspCategory || payload.mitreAttackTechnique) {
      content.push({
        type: 'heading',
        attrs: { level: 4 },
        content: [{ type: 'text', text: 'Taxonomía y Vectores de Ciberseguridad' }],
      });
      const taxItems: unknown[] = [];
      if (payload.cweId) taxItems.push({ type: 'listItem', content: [{ type: 'paragraph', content: [{ type: 'text', text: `CWE: ${payload.cweId}` }] }] });
      if (payload.owaspCategory) taxItems.push({ type: 'listItem', content: [{ type: 'paragraph', content: [{ type: 'text', text: `OWASP: ${payload.owaspCategory}` }] }] });
      if (payload.mitreAttackTechnique) taxItems.push({ type: 'listItem', content: [{ type: 'paragraph', content: [{ type: 'text', text: `MITRE ATT&CK: ${payload.mitreAttackTechnique}` }] }] });
      if (taxItems.length > 0) {
        content.push({ type: 'bulletList', content: taxItems });
      }
    }

    if (payload.complianceControls && payload.complianceControls.length > 0) {
      content.push({
        type: 'heading',
        attrs: { level: 4 },
        content: [{ type: 'text', text: 'Controles Normativos GRC Impactados' }],
      });
      content.push({
        type: 'bulletList',
        content: payload.complianceControls.map((c) => ({
          type: 'listItem',
          content: [
            {
              type: 'paragraph',
              content: [{ type: 'text', text: `[${c.frameworkName}] ${c.code} - ${c.title}` }],
            },
          ],
        })),
      });
    }

    if (payload.customNotes) {
      content.push({
        type: 'heading',
        attrs: { level: 4 },
        content: [{ type: 'text', text: 'Notas del Analista de Seguridad' }],
      });
      content.push({
        type: 'paragraph',
        content: [{ type: 'text', text: payload.customNotes }],
      });
    }

    return {
      type: 'doc',
      version: 1,
      content,
    };
  }
}
