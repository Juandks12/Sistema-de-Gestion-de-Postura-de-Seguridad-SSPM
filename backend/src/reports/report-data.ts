import { AssetType, FindingCategory, FindingSeverity, ReportType, ScanType } from '@prisma/client';
import { SEVERITY_ORDER, SeverityCounts } from '../risk/scoring';

export interface ReportFinding {
  id: string;
  ruleId: string;
  category: FindingCategory;
  severity: FindingSeverity;
  cvssScore: number | null;
  title: string;
  description: string;
  recommendation: string;
  location: string;
  evidence: Record<string, unknown> | null;
  firstSeenAt: Date;
  lastSeenAt: Date;
}

export interface ReportPort {
  port: number;
  protocol: string;
  serviceName: string | null;
  product: string | null;
  version: string | null;
}

export interface ReportAsset {
  id: string;
  type: AssetType;
  value: string;
  name: string | null;
  isActive: boolean;
  scored: boolean;
  score: number | null;
  grade: string | null;
  counts: SeverityCounts;
  lastScannedAt: Date | null;
  lastScanByType: Partial<Record<ScanType, Date | null>>;
  openPorts: ReportPort[];
  portScanAt: Date | null;
  findings: ReportFinding[];
  excluded: { accepted: number; falsePositive: number };
}

export interface ReportData {
  type: ReportType;
  generatedAt: Date;
  generatedBy: string;
  organizationName: string;
  scope: { kind: 'ORGANIZATION' } | { kind: 'ASSET'; value: string; name: string | null };
  score: {
    score: number | null;
    grade: string | null;
    label: string;
    description: string;
    counts: SeverityCounts;
    scoredAssets: number;
    totalAssets: number;
    weekAgoScore: number | null;
  };
  history: Array<{ date: Date; score: number | null }>;
  assets: ReportAsset[];
  alerts: { last30Days: number; unacknowledged: number };
}

export const SEVERITY_LABEL: Record<FindingSeverity, string> = {
  CRITICAL: 'Crítica',
  HIGH: 'Alta',
  MEDIUM: 'Media',
  LOW: 'Baja',
  INFO: 'Informativa',
};

export const SCAN_TYPE_LABEL: Record<ScanType, string> = {
  PORT_SCAN: 'Puertos y servicios',
  WEB_HEADERS: 'Cabeceras HTTP',
  SSL_CERT: 'Certificado TLS',
  SENSITIVE_PATHS: 'Rutas sensibles',
};

export function severityRank(s: FindingSeverity): number {
  return SEVERITY_ORDER.indexOf(s);
}

export function assetLabel(a: { value: string; name: string | null }): string {
  return a.name ? `${a.name} (${a.value})` : a.value;
}

/** Hallazgos abiertos de todo el alcance, del más grave al menos grave. */
export function prioritizedFindings(data: ReportData): Array<ReportFinding & { asset: string }> {
  return data.assets
    .flatMap((a) => a.findings.map((f) => ({ ...f, asset: a.value })))
    .sort((x, y) => severityRank(x.severity) - severityRank(y.severity) || (y.cvssScore ?? 0) - (x.cvssScore ?? 0));
}

export interface RecommendationGroup {
  ruleId: string;
  severity: FindingSeverity;
  title: string;
  recommendation: string;
  occurrences: number;
  assets: string[];
}

/**
 * Agrupa los hallazgos abiertos por regla: cada grupo es una acción de
 * remediación concreta (sección 9.4), ordenada por severidad y alcance.
 */
export function groupRecommendations(data: ReportData, limit = 8): RecommendationGroup[] {
  const groups = new Map<string, RecommendationGroup>();
  for (const f of prioritizedFindings(data)) {
    if (f.severity === FindingSeverity.INFO) continue;
    const g = groups.get(f.ruleId);
    if (!g) {
      groups.set(f.ruleId, {
        ruleId: f.ruleId,
        severity: f.severity,
        title: f.title,
        recommendation: f.recommendation,
        occurrences: 1,
        assets: [f.asset],
      });
      continue;
    }
    g.occurrences += 1;
    if (!g.assets.includes(f.asset)) g.assets.push(f.asset);
    if (severityRank(f.severity) < severityRank(g.severity)) g.severity = f.severity;
  }
  return [...groups.values()]
    .sort((a, b) => severityRank(a.severity) - severityRank(b.severity) || b.occurrences - a.occurrences)
    .slice(0, limit);
}

function plural(n: number, one: string, many: string): string {
  return `${n} ${n === 1 ? one : many}`;
}

/** Párrafos del resumen ejecutivo en lenguaje de negocio (sección 9.1). */
export function executiveSummary(data: ReportData): string[] {
  const s = data.score;
  const subject = data.scope.kind === 'ASSET' ? `el activo ${data.scope.value}` : data.organizationName;
  const paragraphs: string[] = [];

  if (s.score === null) {
    paragraphs.push(
      `Todavía no hay información suficiente para calificar la postura de seguridad de ${subject}: ` +
        'ningún activo tiene un escaneo completado. Lance una auditoría completa para obtener la primera evaluación.',
    );
    return paragraphs;
  }

  paragraphs.push(
    `La postura de seguridad de ${subject} se califica como ${s.label.toLowerCase()} ` +
      `(${s.score}/100, grado ${s.grade}). ${s.description}`,
  );

  const urgent = s.counts.CRITICAL + s.counts.HIGH;
  const open = SEVERITY_ORDER.reduce((acc, sev) => acc + s.counts[sev], 0);
  if (open === 0) {
    paragraphs.push('No hay hallazgos abiertos en este momento.');
  } else {
    const parts = [
      s.counts.CRITICAL ? plural(s.counts.CRITICAL, 'crítico', 'críticos') : null,
      s.counts.HIGH ? plural(s.counts.HIGH, 'de severidad alta', 'de severidad alta') : null,
      s.counts.MEDIUM ? plural(s.counts.MEDIUM, 'de severidad media', 'de severidad media') : null,
      s.counts.LOW ? plural(s.counts.LOW, 'de severidad baja', 'de severidad baja') : null,
    ].filter(Boolean);
    paragraphs.push(
      `Hay ${plural(open, 'hallazgo abierto', 'hallazgos abiertos')}${parts.length ? ` (${parts.join(', ')})` : ''}. ` +
        (urgent > 0
          ? `${plural(urgent, 'requiere', 'requieren')} atención prioritaria por su severidad crítica o alta.`
          : 'Ninguno es de severidad crítica o alta.'),
    );
  }

  if (s.weekAgoScore !== null) {
    const delta = s.score - s.weekAgoScore;
    paragraphs.push(
      delta === 0
        ? 'La puntuación se mantiene igual que hace una semana.'
        : `Respecto a hace una semana, la puntuación ${delta > 0 ? 'mejoró' : 'empeoró'} ${Math.abs(delta)} ` +
            `punto${Math.abs(delta) === 1 ? '' : 's'} (de ${s.weekAgoScore} a ${s.score}).`,
    );
  }

  if (data.scope.kind === 'ORGANIZATION') {
    paragraphs.push(
      `Se monitorean ${plural(s.totalAssets, 'activo', 'activos')}, de los cuales ` +
        `${plural(s.scoredAssets, 'tiene', 'tienen')} al menos una evaluación completa.`,
    );
  }
  return paragraphs;
}

/** Evidencia en una línea legible, sin estructuras anidadas largas. */
export function formatEvidence(evidence: Record<string, unknown> | null, max = 400): string {
  if (!evidence) return '';
  const parts: string[] = [];
  for (const [key, value] of Object.entries(evidence)) {
    if (value === null || value === undefined || value === '') continue;
    let text: string;
    if (Array.isArray(value)) text = value.map((v) => (typeof v === 'object' ? JSON.stringify(v) : String(v))).join(', ');
    else if (typeof value === 'object') text = JSON.stringify(value);
    else text = String(value);
    parts.push(`${key}: ${text}`);
  }
  const joined = parts.join(' · ');
  return joined.length > max ? `${joined.slice(0, max - 1)}…` : joined;
}

const WIN_ANSI_EXTRA = new Set('€‚ƒ„…†‡ˆ‰Š‹ŒŽ‘’“”•–—˜™š›œžŸ'.split(''));

/**
 * Las fuentes estándar de PDF solo cubren WinAnsi (Latin-1 ampliado): los
 * acentos y la ñ del español sí, pero no emojis ni otros alfabetos. Se
 * sustituye cualquier otro carácter para no producir texto corrupto.
 */
export function pdfSafe(text: string): string {
  let out = '';
  for (const ch of text.normalize('NFC')) {
    const code = ch.codePointAt(0) ?? 0;
    if (ch === '\n' || ch === '\t') out += ch;
    else if (code < 0x20 || (code >= 0x7f && code < 0xa0)) continue;
    else if (code <= 0xff || WIN_ANSI_EXTRA.has(ch)) out += ch;
    else if (ch === '→') out += '->';
    else if (ch === '≥') out += '>=';
    else if (ch === '≤') out += '<=';
    else out += '?';
  }
  return out;
}
