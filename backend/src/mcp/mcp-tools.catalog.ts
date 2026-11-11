export interface McpToolDefinition {
  name: string;
  description: string;
  inputSchema: {
    type: 'object';
    properties: Record<string, unknown>;
    required?: string[];
  };
}

export const MCP_TOOLS_CATALOG: McpToolDefinition[] = [
  {
    name: 'sspm_get_posture',
    description:
      'Obtiene la postura de seguridad global de la organización: Security Score actual (0-100), calificación por letra (A-F), total de activos auditados, desglose de hallazgos abiertos por severidad (CRITICAL, HIGH, MEDIUM, LOW) y estado general de riesgo.',
    inputSchema: {
      type: 'object',
      properties: {
        assetId: {
          type: 'string',
          description: 'UUID opcional de un activo para obtener la postura granular del activo en vez de toda la organización.',
        },
      },
    },
  },
  {
    name: 'sspm_list_critical_findings',
    description:
      'Lista los hallazgos de seguridad abiertos de severidad CRITICAL o HIGH en la organización, incluyendo regla (ruleId), activo afectado, ubicación técnica, evidencia y puntaje CVSS.',
    inputSchema: {
      type: 'object',
      properties: {
        limit: {
          type: 'number',
          description: 'Número máximo de hallazgos a retornar (por defecto 10, máx 50).',
        },
        severity: {
          type: 'string',
          enum: ['CRITICAL', 'HIGH', 'ALL'],
          description: 'Filtro de severidad: CRITICAL (solo críticos), HIGH (solo altos) o ALL (críticos y altos).',
        },
        assetId: {
          type: 'string',
          description: 'UUID opcional para filtrar únicamente los hallazgos de un activo específico.',
        },
      },
    },
  },
  {
    name: 'sspm_trigger_scan',
    description:
      'Inicia un escaneo de seguridad bajo demanda en un activo específico (PORT_SCAN, WEB_HEADERS, SSL_CERT, SENSITIVE_PATHS). Requiere que el activo esté activo y autorizado.',
    inputSchema: {
      type: 'object',
      properties: {
        assetId: {
          type: 'string',
          description: 'UUID del activo sobre el cual ejecutar el escaneo.',
        },
        scanType: {
          type: 'string',
          enum: ['PORT_SCAN', 'WEB_HEADERS', 'SSL_CERT', 'SENSITIVE_PATHS', 'SUBDOMAIN_DISCOVERY', 'EMAIL_SECURITY'],
          description: 'Tipo de escaneo de seguridad a encolar y ejecutar.',
        },
      },
      required: ['assetId', 'scanType'],
    },
  },
  {
    name: 'sspm_query_compliance_gap',
    description:
      'Evalúa la postura de cumplimiento normativo frente a un estándar GRC (ISO 27001:2022, PCI-DSS v4.0, NIST CSF 2.0, CIS Controls v8, SOC 2 Type II), retornando porcentaje global, controles en regla y brechas identificadas.',
    inputSchema: {
      type: 'object',
      properties: {
        framework: {
          type: 'string',
          enum: ['ISO_27001', 'PCI_DSS', 'SOC_2', 'NIST_CSF', 'CIS_CONTROLS'],
          description: 'Marco normativo o estándar GRC a evaluar.',
        },
      },
      required: ['framework'],
    },
  },
  {
    name: 'sspm_get_hardening_guide',
    description:
      'Consulta el motor RAG de ciberseguridad con pgvector para recuperar guías oficiales de bastionado técnico y fragmentos de código de remediación en Infraestructura como Código (Terraform, Nginx, Ansible, Dockerfile, OpenSSH).',
    inputSchema: {
      type: 'object',
      properties: {
        query: {
          type: 'string',
          description: 'Consulta técnica semántica (ej. "HSTS Nginx config", "S3 public bucket terraform", "SSH PermitRootLogin", "CVE-2024-6387 regreSSHion").',
        },
        limit: {
          type: 'number',
          description: 'Cantidad máxima de fragmentos o guías a recuperar (por defecto 3).',
        },
      },
      required: ['query'],
    },
  },
];
