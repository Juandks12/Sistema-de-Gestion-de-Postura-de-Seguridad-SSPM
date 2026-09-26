import { Asset, AssetType, FindingCategory, FindingSeverity, ScanType } from '@prisma/client';
import { NmapPort } from './nmap/nmap.types';
import { ResolvedTarget } from './target-resolver';

/** Hallazgo producido por un escáner antes de persistirse (RF-08). */
export interface FindingDraft {
  /** Identificador de la regla del catálogo (src/findings/rules.catalog.ts). */
  ruleId: string;
  /** Dónde se detectó: "tcp/22", "https://host/", "https://host/.env"... */
  location: string;
  /** Datos concretos que sustentan el hallazgo. Nunca debe incluir secretos. */
  evidence?: Record<string, unknown>;
  /** Sobrescriben el texto o severidad del catálogo cuando la regla es genérica. */
  title?: string;
  description?: string;
  recommendation?: string;
  severity?: FindingSeverity;
  /** Puntuación CVSS concreta (p. ej. la del CVE más grave) en lugar de la de referencia de la regla. */
  cvss?: number;
}

/** Puerto abierto conocido por un escaneo de puertos anterior. */
export interface OpenPortHint {
  port: number;
  protocol: string;
  serviceName: string | null;
  tunnel: string | null;
}

/** Contexto que el worker entrega a cada escáner. */
export interface ScanContext {
  scanId: string;
  organizationId: string;
  asset: Asset;
  /** Objetivo ya resuelto y validado (IP literal). Nulo en los escáneres pasivos. */
  target: ResolvedTarget | null;
  allowPrivate: boolean;
  /** Puertos abiertos del último escaneo de puertos completado del activo. */
  openPorts: OpenPortHint[];
  /** Se dispara por cancelación, timeout o apagado. `signal.reason` indica el motivo. */
  signal: AbortSignal;
  timeoutMs: number;
}

/** Resultado de un escáner. El worker se encarga de persistirlo. */
export interface ScanOutcome {
  parameters: Record<string, unknown>;
  rawResult: unknown;
  summary: Record<string, unknown>;
  /** Solo para PORT_SCAN: puertos a guardar en scan_ports. */
  ports?: NmapPort[];
  findings: FindingDraft[];
  /**
   * Categorías que el escáner no pudo evaluar por completo (p. ej. NVD no
   * respondió). Sus hallazgos abiertos se conservan en lugar de darse por resueltos.
   */
  incompleteCategories?: FindingCategory[];
  /** Solo para SUBDOMAIN_DISCOVERY: nombres encontrados en Certificate Transparency. */
  discoveredHosts?: DiscoveredHostDraft[];
}

/** Subdominio encontrado por el descubrimiento pasivo. */
export interface DiscoveredHostDraft {
  hostname: string;
  resolves: boolean;
  addresses: string[];
  wildcard: boolean;
  lastCertificateAt: Date | null;
}

export interface Scanner {
  readonly type: ScanType;
  /** Tipos de activo a los que aplica (por defecto, todos). */
  readonly assetTypes?: readonly AssetType[];
  /**
   * Los escáneres pasivos solo consultan DNS o fuentes públicas: no se
   * conectan al activo, así que no necesitan resolverlo a una IP.
   */
  readonly passive?: boolean;
  run(ctx: ScanContext): Promise<ScanOutcome>;
}

/** true si el escáner puede ejecutarse sobre un activo de ese tipo. */
export function scannerApplies(scanner: Scanner, assetType: AssetType): boolean {
  return !scanner.assetTypes || scanner.assetTypes.includes(assetType);
}

/** Objetivo resuelto de un escáner activo (el worker siempre lo entrega a estos escáneres). */
export function requireTarget(ctx: ScanContext): ResolvedTarget {
  if (!ctx.target) {
    throw new Error(`El escaneo ${ctx.scanId} no tiene un objetivo resuelto`);
  }
  return ctx.target;
}

/** Token de inyección para registrar los escáneres disponibles. */
export const SCANNERS = Symbol('SCANNERS');

export type AbortReason = 'cancelled' | 'timeout' | 'shutdown';

export function abortReason(signal: AbortSignal): AbortReason | null {
  if (!signal.aborted) return null;
  const reason = signal.reason as unknown;
  return reason === 'cancelled' || reason === 'timeout' || reason === 'shutdown'
    ? reason
    : 'cancelled';
}
