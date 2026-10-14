import { AlertType, FindingCategory, FindingSeverity, ScanType } from '@prisma/client';
import type { OpenedFinding } from '../findings/findings.service';
import { calculateScoreStats, evaluateScoreAnomaly, SEVERITY_ORDER } from '../risk/scoring';

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
 * - NEW_SUBDOMAIN: subdominios que aparecen por primera vez en Certificate
 *   Transparency y no están en el inventario. El primer descubrimiento es la
 *   línea base y no alerta.
 * - SCORE_ANOMALY: caída anómala en el Security Score respecto al histórico
 *   del activo o descensos abruptos que sugieren exposición simultánea.
 */

/** Subdominios que se enumeran en el texto de la alerta (el resto se resume). */
const MAX_HOSTS_IN_MESSAGE = 10;

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
  /** Subdominios nuevos fuera del inventario; null o ausente si no aplica (o es la línea base). */
  newHosts?: string[] | null;
  /** Información para evaluar anomalías en el Security Score (null si es la línea base o no hay histórico). */
  scoreChange?: ScoreAnomalyInput | null;
}

export interface ScoreAnomalyInput {
  currentScore: number;
  previousScore: number;
  historyScores?: number[];
  openedFindings?: Array<{ ruleId: string; severity: FindingSeverity; title: string; location: string }>;
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

  if (input.scan.type === ScanType.SUBDOMAIN_DISCOVERY && input.newHosts && input.newHosts.length > 0) {
    const hosts = input.newHosts;
    const shown = hosts.slice(0, MAX_HOSTS_IN_MESSAGE).join(', ');
    const rest = hosts.length > MAX_HOSTS_IN_MESSAGE ? ` y ${hosts.length - MAX_HOSTS_IN_MESSAGE} más` : '';
    alerts.push({
      type: AlertType.NEW_SUBDOMAIN,
      severity: FindingSeverity.MEDIUM,
      title:
        hosts.length === 1
          ? `Nuevo subdominio de ${input.asset.value}: ${hosts[0]}`
          : `${hosts.length} subdominios nuevos de ${input.asset.value}`,
      message:
        `Se emitieron certificados TLS para ${hosts.length === 1 ? 'un subdominio' : 'subdominios'} de ${label} ` +
        `que no están en el inventario: ${shown}${rest}. ` +
        'Confirme que son de su organización y regístrelos como activos para auditarlos; si no los reconoce, ' +
        'revise quién los está publicando (puede ser shadow IT o una emisión no autorizada).',
      data: { hosts },
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

  if (input.scoreChange) {
    const enrichedChange: ScoreAnomalyInput = {
      ...input.scoreChange,
      openedFindings:
        input.scoreChange.openedFindings ??
        input.opened.map((f) => ({
          ruleId: f.ruleId,
          severity: f.severity,
          title: f.title,
          location: f.location,
        })),
    };
    const scoreAlert = detectScoreAnomaly(input.asset, enrichedChange);
    if (scoreAlert) {
      alerts.push(scoreAlert);
    }
  }

  return alerts;
}

export function detectScoreAnomaly(
  asset: { value: string; name: string | null },
  input: ScoreAnomalyInput,
): AlertDraft | null {
  const { currentScore, previousScore, historyScores = [], openedFindings = [] } = input;
  const evalResult = evaluateScoreAnomaly(currentScore, previousScore, historyScores);

  if (!evalResult.isAnomaly || !evalResult.severity) return null;

  const label = assetLabel(asset);
  const { drop, mean, stdDev, zScore, severity } = evalResult;

  const statText =
    mean !== undefined && stdDev !== undefined && zScore !== undefined
      ? `, desviándose marcadamente de su promedio histórico (${mean} ± ${stdDev}, z=${zScore})`
      : '';

  const topDrivers = openedFindings
    .slice()
    .sort((a, b) => severityRank(a.severity) - severityRank(b.severity))
    .slice(0, 3);

  const driversText =
    topDrivers.length > 0
      ? ` Coincide con la detección de nuevos hallazgos: ${topDrivers.map((d) => `${d.title} (${d.location})`).join(', ')}.`
      : '';

  return {
    type: AlertType.SCORE_ANOMALY,
    severity,
    title: `Caída anómala de Security Score en ${asset.value}: -${drop} pts (${previousScore} → ${currentScore})`,
    message:
      `El Security Score de ${label} sufrió una degradación atípica de ${drop} puntos ` +
      `(pasó de ${previousScore} a ${currentScore})${statText}.${driversText} ` +
      `Esta caída abrupta suele indicar la exposición de servicios críticos o la detección simultánea de nuevas vulnerabilidades. ` +
      `Revise los hallazgos recientes para mitigar el impacto antes de la próxima auditoría.`,
    data: {
      currentScore,
      previousScore,
      drop,
      mean: mean ?? null,
      stdDev: stdDev ?? null,
      zScore: zScore ?? null,
      sampleSize: historyScores.length,
      penaltyDrivers: topDrivers,
    },
  };
}

export { calculateScoreStats, evaluateScoreAnomaly };

/** Puertos abiertos de `current` que no estaban en `previous`. */
export function diffOpenPorts(previous: PortInfo[], current: PortInfo[]): PortInfo[] {
  const before = new Set(previous.map((p) => `${p.protocol}/${p.port}`));
  return current.filter((p) => !before.has(`${p.protocol}/${p.port}`));
}

export { SEVERITY_LABEL };
