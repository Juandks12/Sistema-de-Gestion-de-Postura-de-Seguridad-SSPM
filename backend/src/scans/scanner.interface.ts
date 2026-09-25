import { Asset, FindingSeverity, ScanType } from '@prisma/client';
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
  /** Objetivo ya resuelto y validado (IP literal). */
  target: ResolvedTarget;
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
}

export interface Scanner {
  readonly type: ScanType;
  run(ctx: ScanContext): Promise<ScanOutcome>;
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
