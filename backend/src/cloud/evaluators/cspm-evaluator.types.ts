import {
  CloudProvider,
  CloudResourceType,
  FindingCategory,
  FindingSeverity,
} from '@prisma/client';

export interface DiscoveredCloudResource {
  /** Identificador canónico único: ARN en AWS o Resource ID en Azure */
  nativeId: string;
  /** Nombre legible del recurso */
  name: string;
  resourceType: CloudResourceType;
  region: string | null;
  /** Configuración recolectada del proveedor cloud */
  configuration: Record<string, unknown>;
  /** Etiquetas clave-valor del recurso */
  tags?: Record<string, string> | null;
}

export interface CspmFindingDraft {
  /** Código de regla del catálogo CSPM_RULES (p. ej. AWS-S3-PUBLIC-READ, AZ-NSG-SSH-OPEN) */
  ruleId: string;
  /** ARN o Resource ID afectado (se usa como location y para calcular el fingerprint sha256) */
  nativeId: string;
  resourceName: string;
  resourceType: CloudResourceType;
  region: string | null;
  descriptionOverride?: string;
  evidence: Record<string, unknown>;
}

export interface CloudAuditExecutionResult {
  provider: CloudProvider;
  accountOrSubscriptionId: string;
  simulated: boolean;
  evaluatedRulesCount: number;
  resources: DiscoveredCloudResource[];
  findings: CspmFindingDraft[];
  warnings: string[];
}

export interface CloudAuditStats {
  resourcesDiscovered: number;
  findingsCreated: number;
  findingsUpdated: number;
  findingsReopened: number;
  findingsResolved: number;
  activeFindings: number;
  bySeverity: Record<FindingSeverity, number>;
  byCategory: Partial<Record<FindingCategory, number>>;
  score: number | null;
  grade: string | null;
}
