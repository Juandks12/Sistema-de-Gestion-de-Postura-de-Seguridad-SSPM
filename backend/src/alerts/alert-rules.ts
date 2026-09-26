import { AlertType, FindingCategory, FindingSeverity, ScanType } from '@prisma/client';
import type { OpenedFinding } from '../findings/findings.service';
import { SEVERITY_ORDER } from '../risk/scoring';

/**
 * Reglas de alertas tempranas (RF-10, sección 10.1). Funciones puras: reciben
 * lo que cambió en un escaneo completado y devuelven las alertas a emitir.
 *
 * - NEW_OPEN_PORT: puertos abiertos que no estaban en el escaneo de puertos
 *   anterior del activo. El primer escaneo es la línea base y no alerta.
 * - CERT_EXPIRING: el certificado caducó o caduca en menos de 30 días
 *   (solo cuando el hallazgo aparece o se reabre, no en cada escaneo).
 * - CRITICAL_FINDING: hallazgos críticos nuevos o reabiertos que no estén ya
 *   cubiertos por las dos alertas anteriores.
 */

export const CERT_EXPIRY_RULES = ['TLS-EXPIRED', 'TLS-EXPIRING-7D', 'TLS-EXPIRING-30D'] as const;

export interface PortInfo {
  port: number;
  protocol: string;
  serviceName: string | null;
  product: string | null;
  version: string | null;
}

export interface AlertDetectionInput {
  asset: { id: string; value: string; name: string | null };
  scan: { id: string; type: ScanType };
  /** Hallazgos que pasaron a OPEN en este escaneo. */
  opened: OpenedFinding[];
  /** Puertos abiertos nuevos frente al escaneo de puertos anterior; null si no hay anterior (línea base). */
  newOpenPorts: PortInfo[] | null;
}

export interface AlertDraft {
  type: AlertType;
  severity: FindingSeverity;
  title: string;
  message: string;
  data: Record<string, unknown>;
}

const SEVERITY_LABEL: Record<FindingSeverity, string> = {
  CRITICAL: 'crítica',
  HIGH: 'alta',
  MEDIUM: 'media',
  LOW: 'baja',
  INFO: 'informativa',
};

export function severityRank(severity: FindingSeverity): number {
  return SEVERITY_ORDER.indexOf(severity);
}

/** true si `severity` es igual o más grave que `threshold`. */
export function meetsThreshold(severity: FindingSeverity, threshold: FindingSeverity): boolean {
  return severityRank(severity) <= severityRank(threshold);
}

export function maxSeverity(values: FindingSeverity[], fallback: FindingSeverity): FindingSeverity {
  return values.reduce((acc, s) => (severityRank(s) < severityRank(acc) ? s : acc), fallback);
}

export function assetLabel(asset: { value: string; name: string | null }): string {
  return asset.name ? `${asset.name} (${asset.value})` : asset.value;
}

function describePort(p: PortInfo): string {
  const service = [p.serviceName, p.product, p.version].filter(Boolean).join(' ');
  return `${p.protocol}/${p.port}${service ? ` (${service})` : ''}`;
}

export function detectAlerts(input: AlertDetectionInput): AlertDraft[] {
  const alerts: AlertDraft[] = [];
  const label = assetLabel(input.asset);
  const covered = new Set<string>();

  if (input.scan.type === ScanType.PORT_SCAN && input.newOpenPorts && input.newOpenPorts.length > 0) {
    const ports = [...input.newOpenPorts].sort((a, b) => a.port - b.port);
    const locations = new Set(ports.map((p) => `${p.protocol}/${p.port}`));
    const related = input.opened.filter(
      (f) => f.category === FindingCategory.EXPOSED_SERVICE && locations.has(f.location),
    );
    related.forEach((f) => covered.add(f.id));
    const severity = maxSeverity(
      related.map((f) => f.severity),
      FindingSeverity.MEDIUM,
    );
    const list = ports.map(describePort).join(', ');
    alerts.push({
      type: AlertType.NEW_OPEN_PORT,
      severity,
      title:
        ports.length === 1
          ? `Nuevo puerto abierto en ${input.asset.value}: ${ports[0].protocol}/${ports[0].port}`
          : `${ports.length} puertos nuevos abiertos en ${input.asset.value}`,
      message:
        `El último escaneo de ${label} detectó ${ports.length === 1 ? 'un puerto abierto' : 'puertos abiertos'} ` +
        `que no estaban expuestos en el escaneo anterior: ${list}. ` +
        'Verifique que la exposición es intencionada; si no lo es, ciérrelo o restrinja el acceso por firewall.',
      data: {
        ports,
        findings: related.map((f) => ({ id: f.id, ruleId: f.ruleId, severity: f.severity, title: f.title })),
      },
    });
  }

  for (const f of input.opened) {
    if (!(CERT_EXPIRY_RULES as readonly string[]).includes(f.ruleId)) continue;
    covered.add(f.id);
    const validTo = typeof f.evidence.validTo === 'string' ? f.evidence.validTo : null;
    const days = typeof f.evidence.daysUntilExpiry === 'number' ? f.evidence.daysUntilExpiry : null;
    const expired = f.ruleId === 'TLS-EXPIRED';
    const when = validTo ? new Date(validTo).toISOString().slice(0, 10) : null;
    alerts.push({
      type: AlertType.CERT_EXPIRING,
      severity: f.severity,
      title: expired
        ? `Certificado TLS caducado en ${input.asset.value}`
        : `Certificado TLS de ${input.asset.value} caduca ${days !== null ? `en ${days} día(s)` : 'pronto'}`,
      message: expired
        ? `El certificado de ${f.location} caducó${when ? ` el ${when}` : ''}. Los navegadores ya muestran advertencias a los usuarios; renuévelo de inmediato.`
        : `El certificado de ${f.location} caduca${when ? ` el ${when}` : ''}${days !== null ? ` (quedan ${days} día(s))` : ''}. ` +
          'Renuévelo antes de esa fecha para evitar una interrupción del servicio.',
      data: { findingId: f.id, ruleId: f.ruleId, location: f.location, validTo, daysUntilExpiry: days },
    });
  }

  const critical = input.opened.filter((f) => f.severity === FindingSeverity.CRITICAL && !covered.has(f.id));
  if (critical.length > 0) {
    alerts.push({
      type: AlertType.CRITICAL_FINDING,
      severity: FindingSeverity.CRITICAL,
      title:
        critical.length === 1
          ? `Hallazgo crítico en ${input.asset.value}: ${critical[0].title}`
          : `${critical.length} hallazgos críticos nuevos en ${input.asset.value}`,
      message:
        `Se detectaron ${critical.length === 1 ? 'un hallazgo' : `${critical.length} hallazgos`} de severidad ` +
        `${SEVERITY_LABEL.CRITICAL} en ${label}: ` +
        critical.map((f) => `${f.title} (${f.location})`).join('; ') +
        '. Revíselos en la plataforma y aplique la recomendación de mitigación cuanto antes.',
      data: { findings: critical.map((f) => ({ id: f.id, ruleId: f.ruleId, title: f.title, location: f.location })) },
    });
  }

  return alerts;
}

/** Puertos abiertos de `current` que no estaban en `previous`. */
export function diffOpenPorts(previous: PortInfo[], current: PortInfo[]): PortInfo[] {
  const before = new Set(previous.map((p) => `${p.protocol}/${p.port}`));
  return current.filter((p) => !before.has(`${p.protocol}/${p.port}`));
}

export { SEVERITY_LABEL };
