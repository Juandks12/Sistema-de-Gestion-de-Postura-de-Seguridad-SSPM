import { FindingCategory, FindingSeverity } from '@prisma/client';
import {
  COMPLIANCE_CONTROLS,
  ComplianceFramework,
  FRAMEWORKS_METADATA,
} from '../compliance/compliance.catalog';
import { FindingSourceType } from './dto/list-findings.query';

export { FindingSourceType };

export interface FindingComplianceControlRef {
  id: string;
  framework: ComplianceFramework;
  frameworkName: string;
  code: string;
  title: string;
  domain: string;
}

export interface FindingSecurityTaxonomy {
  cweId: string;
  owaspCategory: string;
  mitreAttackTechnique: string;
}

const CATEGORY_TAXONOMY_DEFAULTS: Record<FindingCategory, FindingSecurityTaxonomy> = {
  [FindingCategory.EXPOSED_SERVICE]: {
    cweId: 'CWE-200: Exposición de Servicios o Información de Red',
    owaspCategory: 'A05:2021 - Security Misconfiguration',
    mitreAttackTechnique: 'T1046 - Network Service Discovery / T1133 - External Remote Services',
  },
  [FindingCategory.HTTP_HEADERS]: {
    cweId: 'CWE-693: Fallo de Mecanismo de Protección Web',
    owaspCategory: 'A05:2021 - Security Misconfiguration',
    mitreAttackTechnique: 'T1189 - Drive-by Compromise / T1190 - Exploit Public-Facing Application',
  },
  [FindingCategory.TLS_CERTIFICATE]: {
    cweId: 'CWE-295 / CWE-326: Validación Impropia de Certificado o Cifrado Insuficiente',
    owaspCategory: 'A02:2021 - Cryptographic Failures',
    mitreAttackTechnique: 'T1557 - Adversary-in-the-Middle (AiTM)',
  },
  [FindingCategory.SENSITIVE_PATH]: {
    cweId: 'CWE-538 / CWE-284: Inserción de Archivos Sensibles o Control de Acceso Inadecuado',
    owaspCategory: 'A01:2021 - Broken Access Control',
    mitreAttackTechnique: 'T1552 - Unsecured Credentials / T1213 - Data from Information Repositories',
  },
  [FindingCategory.VULNERABLE_SOFTWARE]: {
    cweId: 'CWE-1395: Dependencia de Componente de Terceros Vulnerable',
    owaspCategory: 'A06:2021 - Vulnerable and Outdated Components',
    mitreAttackTechnique: 'T1190 - Exploit Public-Facing Application',
  },
  [FindingCategory.EMAIL_SECURITY]: {
    cweId: 'CWE-290: Suplantación de Autenticación por Spoofing de Dominio',
    owaspCategory: 'A07:2021 - Identification and Authentication Failures',
    mitreAttackTechnique: 'T1566 - Phishing / T1656 - Impersonation',
  },
  [FindingCategory.CLOUD_IAM]: {
    cweId: 'CWE-269: Gestión Impropia de Privilegios Cloud IAM',
    owaspCategory: 'A01:2021 - Broken Access Control / A07:2021 - Auth Failures',
    mitreAttackTechnique: 'T1078.004 - Valid Accounts: Cloud Accounts',
  },
  [FindingCategory.CLOUD_STORAGE]: {
    cweId: 'CWE-284 / CWE-311: Almacenamiento Cloud Público o Sin Cifrado',
    owaspCategory: 'A01:2021 - Broken Access Control / A02:2021 - Cryptographic Failures',
    mitreAttackTechnique: 'T1530 - Data from Cloud Storage',
  },
  [FindingCategory.CLOUD_NETWORK]: {
    cweId: 'CWE-284: Reglas de Seguridad de Red Cloud Permisivas',
    owaspCategory: 'A05:2021 - Security Misconfiguration',
    mitreAttackTechnique: 'T1133 - External Remote Services',
  },
  [FindingCategory.CLOUD_COMPUTE]: {
    cweId: 'CWE-250: Ejecución con Privilegios Innecesarios o Metadatos Expuestos',
    owaspCategory: 'A05:2021 - Security Misconfiguration',
    mitreAttackTechnique: 'T1552.005 - Cloud Instance Metadata API',
  },
  [FindingCategory.CLOUD_DATABASE]: {
    cweId: 'CWE-311 / CWE-284: Base de Datos Cloud Expuesta o Sin Cifrado',
    owaspCategory: 'A02:2021 - Cryptographic Failures',
    mitreAttackTechnique: 'T1213 - Data from Information Repositories',
  },
  [FindingCategory.CLOUD_LOGGING]: {
    cweId: 'CWE-778: Registro y Monitoreo Insuficiente de Eventos',
    owaspCategory: 'A09:2021 - Security Logging and Monitoring Failures',
    mitreAttackTechnique: 'T1562.008 - Disable or Modify Cloud Logs',
  },
  [FindingCategory.MALWARE_THREAT]: {
    cweId: 'CWE-506 / CWE-451: Código Malicioso Embebido o Suplantación de Interfaz (Phishing)',
    owaspCategory: 'A08:2021 - Software and Data Integrity Failures / A07:2021 - Auth Failures',
    mitreAttackTechnique: 'T1566 - Phishing / T1204 - User Execution',
  },
};

const RULE_SPECIFIC_TAXONOMY: Record<string, Partial<FindingSecurityTaxonomy>> = {
  'WEB-ECOMMERCE-SRI-MISSING': {
    cweId: 'CWE-353 / CWE-829: Inclusión de Script Externo sin Verificación de Integridad (SRI)',
    owaspCategory: 'A08:2021 - Software and Data Integrity Failures',
    mitreAttackTechnique: 'T1189 - Drive-by Compromise (Magecart / Web Skimming)',
  },
  'WEB-JS-SECRET-EXPOSED': {
    cweId: 'CWE-798: Uso de Credenciales o Llaves API Embebidas en Código Cliente',
    owaspCategory: 'A02:2021 - Cryptographic Failures / A07:2021 - Auth Failures',
    mitreAttackTechnique: 'T1552.001 - Unsecured Credentials: Credentials In Files',
  },
  'WEB-CORS-WILDCARD-CREDENTIALS': {
    cweId: 'CWE-942: Política Cross-Domain Permisiva con Credenciales',
    owaspCategory: 'A05:2021 - Security Misconfiguration',
    mitreAttackTechnique: 'T1539 - Steal Web Session Cookie',
  },
  'DNS-SUBDOMAIN-TAKEOVER': {
    cweId: 'CWE-672: Operación sobre un Recurso o Subdominio Expirado (Dangling DNS)',
    owaspCategory: 'A05:2021 - Security Misconfiguration',
    mitreAttackTechnique: 'T1584.001 - Compromise Infrastructure: Domains',
  },
  'WEB-OPENAPI-UNAUTH-CRITICAL-OPS': {
    cweId: 'CWE-306: Falta de Autenticación para Función Crítica en API',
    owaspCategory: 'API2:2023 - Broken Authentication / A01:2021 - Broken Access Control',
    mitreAttackTechnique: 'T1190 - Exploit Public-Facing Application',
  },
  'WEB-GRAPHQL-INTROSPECTION-ENABLED': {
    cweId: 'CWE-200: Exposición de Esquema Interno GraphQL en Producción',
    owaspCategory: 'API8:2023 - Security Misconfiguration',
    mitreAttackTechnique: 'T1592 - Gather Victim Host Information',
  },
  'WEB-DEBUG-STACKTRACE-EXPOSED': {
    cweId: 'CWE-209: Generación de Mensaje de Error con Información Sensible (Stack Trace)',
    owaspCategory: 'A05:2021 - Security Misconfiguration',
    mitreAttackTechnique: 'T1592 - Gather Victim Host Information',
  },
  'HDR-COOKIE-PREFIX-INVALID': {
    cweId: 'CWE-614 / CWE-565: Configuración Insegura de Prefijos de Cookie (__Host- / __Secure-)',
    owaspCategory: 'A07:2021 - Identification and Authentication Failures',
    mitreAttackTechnique: 'T1539 - Steal Web Session Cookie',
  },
  'HDR-CACHE-CONTROL-MISSING-SENSITIVE': {
    cweId: 'CWE-525: Uso de Caché de Navegador para Información Sensible',
    owaspCategory: 'A04:2021 - Insecure Design',
    mitreAttackTechnique: 'T1005 - Data from Local System',
  },
  'TLS-WEAK-CIPHER': {
    cweId: 'CWE-327: Uso de Algoritmo Criptográfico Roto o Riesgoso',
    owaspCategory: 'A02:2021 - Cryptographic Failures',
    mitreAttackTechnique: 'T1557 - Adversary-in-the-Middle (AiTM)',
  },
  'TLS-NO-FORWARD-SECRECY': {
    cweId: 'CWE-326: Ausencia de Perfect Forward Secrecy (ECDHE/DHE) en TLS',
    owaspCategory: 'A02:2021 - Cryptographic Failures',
    mitreAttackTechnique: 'T1040 - Network Sniffing',
  },
  'TLS-EXCESSIVE-LIFESPAN': {
    cweId: 'CWE-298: Vigencia Excesiva de Certificado TLS (> 398 días CA/B Forum)',
    owaspCategory: 'A02:2021 - Cryptographic Failures',
    mitreAttackTechnique: 'T1588.004 - Digital Certificates',
  },
  'THREAT-EMAIL-PHISHING-BEC': {
    cweId: 'CWE-290 / CWE-451: Suplantación de Identidad en Correo (Phishing / BEC)',
    owaspCategory: 'A07:2021 - Identification and Authentication Failures',
    mitreAttackTechnique: 'T1566.001 / T1566.002 - Spearphishing Attachment & Link',
  },
  'THREAT-FILE-MALICIOUS-HASH': {
    cweId: 'CWE-506: Malware Confirmado por Inteligencia de Amenazas o Firma Ejecutable',
    owaspCategory: 'A08:2021 - Software and Data Integrity Failures',
    mitreAttackTechnique: 'T1204.002 - User Execution: Malicious File',
  },
  'THREAT-FILE-SUSPICIOUS-MACRO-PDF': {
    cweId: 'CWE-829 / CWE-506: Documento con Macros Activas VBA/XLM o Acciones PDF Peligrosas (/JS, /Launch)',
    owaspCategory: 'A08:2021 - Software and Data Integrity Failures',
    mitreAttackTechnique: 'T1059.005 - Command and Scripting Interpreter: Visual Basic',
  },
  'THREAT-URL-MALICIOUS-PHISHING': {
    cweId: 'CWE-601 / CWE-451: URL Maliciosa de Captura de Credenciales o Distribución de Payload',
    owaspCategory: 'A07:2021 - Identification and Authentication Failures',
    mitreAttackTechnique: 'T1566.002 - Phishing: Spearphishing Link',
  },
  'MAIL-SPF-PERMERROR-RISK': {
    cweId: 'CWE-290: Riesgo de Fallo Permanente SPF (>8 consultas DNS, RFC 7208)',
    owaspCategory: 'A05:2021 - Security Misconfiguration',
    mitreAttackTechnique: 'T1566 - Phishing',
  },
  'DNS-WILDCARD-ENABLED': {
    cweId: 'CWE-350: Resolución DNS Comodín (*.dominio) Expuesta',
    owaspCategory: 'A05:2021 - Security Misconfiguration',
    mitreAttackTechnique: 'T1583.001 - Acquire Infrastructure: Domains',
  },
  'DNS-INTERNAL-IP-LEAK': {
    cweId: 'CWE-200: Exposición de Topología de Red Interna en Registros DNS Públicos (RFC 1918)',
    owaspCategory: 'A05:2021 - Security Misconfiguration',
    mitreAttackTechnique: 'T1590.002 - Gather Victim Network Information: DNS',
  },
};

const CONTROLS_BY_RULE_ID = new Map<string, FindingComplianceControlRef[]>();
const CONTROLS_BY_ID_OR_CODE = new Map<string, FindingComplianceControlRef>();

for (const ctrl of COMPLIANCE_CONTROLS) {
  const frameworkMeta = FRAMEWORKS_METADATA[ctrl.framework];
  const ref: FindingComplianceControlRef = {
    id: ctrl.id,
    framework: ctrl.framework,
    frameworkName: frameworkMeta?.name ?? ctrl.framework,
    code: ctrl.code,
    title: ctrl.title,
    domain: ctrl.domain,
  };
  CONTROLS_BY_ID_OR_CODE.set(ctrl.id.toUpperCase(), ref);
  CONTROLS_BY_ID_OR_CODE.set(ctrl.code.toUpperCase(), ref);
  CONTROLS_BY_ID_OR_CODE.set(`${ctrl.framework}:${ctrl.code}`.toUpperCase(), ref);

  for (const rId of ctrl.ruleIds) {
    const list = CONTROLS_BY_RULE_ID.get(rId) ?? [];
    list.push(ref);
    CONTROLS_BY_RULE_ID.set(rId, list);
  }
}

export function resolveFindingSource(finding: {
  ruleId: string;
  category?: FindingCategory;
  cloudAccountId?: string | null;
  evidence?: unknown;
}): FindingSourceType {
  const ev =
    finding.evidence && typeof finding.evidence === 'object'
      ? (finding.evidence as Record<string, unknown>)
      : {};

  if (typeof ev.sourceType === 'string') {
    const st = ev.sourceType.toUpperCase();
    if (
      st === 'PERIMETER_SCAN' ||
      st === 'CLOUD_CSPM' ||
      st === 'THREAT_MALWARE_LAB' ||
      st === 'MANUAL_AUDIT'
    ) {
      return st;
    }
  }

  if (finding.cloudAccountId) {
    return 'CLOUD_CSPM';
  }
  const rId = finding.ruleId ?? '';
  if (rId.startsWith('THREAT-') || rId.startsWith('MALWARE-')) {
    return 'THREAT_MALWARE_LAB';
  }
  if (rId.startsWith('MANUAL-') || ev.manualAudit === true) {
    return 'MANUAL_AUDIT';
  }
  return 'PERIMETER_SCAN';
}

export function resolveSecurityTaxonomy(
  ruleId: string,
  category: FindingCategory,
  evidence?: unknown,
): FindingSecurityTaxonomy {
  const base = CATEGORY_TAXONOMY_DEFAULTS[category] ?? {
    cweId: 'CWE-693: Fallo de Mecanismo de Protección',
    owaspCategory: 'A05:2021 - Security Misconfiguration',
    mitreAttackTechnique: 'T1190 - Exploit Public-Facing Application',
  };
  const specific = RULE_SPECIFIC_TAXONOMY[ruleId] ?? {};
  const ev =
    evidence && typeof evidence === 'object'
      ? (evidence as Record<string, unknown>)
      : {};

  return {
    cweId:
      (typeof ev.cweId === 'string' && ev.cweId.trim()) ||
      specific.cweId ||
      base.cweId,
    owaspCategory:
      (typeof ev.owaspCategory === 'string' && ev.owaspCategory.trim()) ||
      specific.owaspCategory ||
      base.owaspCategory,
    mitreAttackTechnique:
      (typeof ev.mitreAttackTechnique === 'string' && ev.mitreAttackTechnique.trim()) ||
      specific.mitreAttackTechnique ||
      base.mitreAttackTechnique,
  };
}

export function resolveComplianceControls(
  ruleId: string,
  evidence?: unknown,
): FindingComplianceControlRef[] {
  const seen = new Map<string, FindingComplianceControlRef>();

  const direct = CONTROLS_BY_RULE_ID.get(ruleId) ?? [];
  for (const c of direct) {
    seen.set(c.id, c);
  }

  const ev =
    evidence && typeof evidence === 'object'
      ? (evidence as Record<string, unknown>)
      : {};

  if (Array.isArray(ev.complianceControlIds)) {
    for (const rawId of ev.complianceControlIds) {
      if (typeof rawId !== 'string') continue;
      const found = CONTROLS_BY_ID_OR_CODE.get(rawId.trim().toUpperCase());
      if (found) {
        seen.set(found.id, found);
      }
    }
  }

  return [...seen.values()];
}

export function getRuleIdsForFramework(
  framework?: ComplianceFramework,
  controlCode?: string,
): string[] {
  const matching = COMPLIANCE_CONTROLS.filter((ctrl) => {
    if (framework && ctrl.framework !== framework) return false;
    if (
      controlCode &&
      ctrl.code.toLowerCase() !== controlCode.trim().toLowerCase() &&
      ctrl.id.toLowerCase() !== controlCode.trim().toLowerCase()
    ) {
      return false;
    }
    return true;
  });

  const ids = new Set<string>();
  for (const ctrl of matching) {
    for (const rId of ctrl.ruleIds) {
      ids.add(rId);
    }
  }
  return [...ids];
}

export function computeDefaultFindingDueDate(
  severity: FindingSeverity,
  fromDate: Date = new Date(),
): Date {
  const hourMs = 60 * 60 * 1000;
  const dayMs = 24 * hourMs;

  switch (severity) {
    case FindingSeverity.CRITICAL:
      return new Date(fromDate.getTime() + 24 * hourMs);
    case FindingSeverity.HIGH:
      return new Date(fromDate.getTime() + 7 * dayMs);
    case FindingSeverity.MEDIUM:
      return new Date(fromDate.getTime() + 30 * dayMs);
    case FindingSeverity.LOW:
    case FindingSeverity.INFO:
    default:
      return new Date(fromDate.getTime() + 90 * dayMs);
  }
}
