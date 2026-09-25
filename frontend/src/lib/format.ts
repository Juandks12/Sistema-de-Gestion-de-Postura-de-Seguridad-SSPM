import type { FindingCategory, FindingStatus, Grade, ScanStatus, ScanType, Severity } from './types';

const dateTime = new Intl.DateTimeFormat('es', { dateStyle: 'medium', timeStyle: 'short' });
const dateOnly = new Intl.DateTimeFormat('es', { day: 'numeric', month: 'short' });
const relative = new Intl.RelativeTimeFormat('es', { numeric: 'auto' });

export function formatDateTime(value: string | null | undefined): string {
  if (!value) return '—';
  return dateTime.format(new Date(value));
}

export function formatShortDate(value: string): string {
  return dateOnly.format(new Date(value));
}

export function timeAgo(value: string | null | undefined): string {
  if (!value) return 'nunca';
  const diff = (new Date(value).getTime() - Date.now()) / 1000;
  const abs = Math.abs(diff);
  if (abs < 60) return relative.format(Math.round(diff), 'second');
  if (abs < 3600) return relative.format(Math.round(diff / 60), 'minute');
  if (abs < 86400) return relative.format(Math.round(diff / 3600), 'hour');
  if (abs < 86400 * 30) return relative.format(Math.round(diff / 86400), 'day');
  return dateTime.format(new Date(value));
}

/** Versión compacta para espacios reducidos: "hace 28 s", "hace 5 min", "hace 3 h", "hace 2 d". */
export function timeAgoShort(value: string | null | undefined): string {
  if (!value) return 'nunca';
  const s = Math.max(0, (Date.now() - new Date(value).getTime()) / 1000);
  if (s < 60) return `hace ${Math.round(s)} s`;
  if (s < 3600) return `hace ${Math.round(s / 60)} min`;
  if (s < 86400) return `hace ${Math.round(s / 3600)} h`;
  if (s < 86400 * 30) return `hace ${Math.round(s / 86400)} d`;
  return dateOnly.format(new Date(value));
}

export function duration(start: string | null, end: string | null): string {
  if (!start || !end) return '—';
  const s = Math.max(0, (new Date(end).getTime() - new Date(start).getTime()) / 1000);
  if (s < 1) return '< 1 s';
  if (s < 60) return `${Math.round(s)} s`;
  return `${Math.floor(s / 60)} min ${Math.round(s % 60)} s`;
}

export const SEVERITY_LABEL: Record<Severity, string> = {
  CRITICAL: 'Crítica',
  HIGH: 'Alta',
  MEDIUM: 'Media',
  LOW: 'Baja',
  INFO: 'Informativa',
};

export const SEVERITY_ORDER: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

export const STATUS_LABEL: Record<FindingStatus, string> = {
  OPEN: 'Abierto',
  RESOLVED: 'Resuelto',
  ACCEPTED: 'Riesgo aceptado',
  FALSE_POSITIVE: 'Falso positivo',
};

export const CATEGORY_LABEL: Record<FindingCategory, string> = {
  EXPOSED_SERVICE: 'Servicio expuesto',
  HTTP_HEADERS: 'Cabeceras HTTP',
  TLS_CERTIFICATE: 'Certificado TLS',
  SENSITIVE_PATH: 'Ruta sensible',
};

export const SCAN_TYPE_LABEL: Record<ScanType, string> = {
  PORT_SCAN: 'Puertos y servicios',
  WEB_HEADERS: 'Cabeceras HTTP',
  SSL_CERT: 'Certificado TLS',
  SENSITIVE_PATHS: 'Rutas sensibles',
};

export const SCAN_STATUS_LABEL: Record<ScanStatus, string> = {
  PENDING: 'En cola',
  RUNNING: 'En ejecución',
  COMPLETED: 'Completado',
  FAILED: 'Fallido',
  CANCELLED: 'Cancelado',
};

export const GRADE_LABEL: Record<Grade, string> = {
  A: 'Excelente',
  B: 'Buena',
  C: 'Aceptable',
  D: 'Deficiente',
  F: 'Crítica',
};

export function cvss(value: string | number | null | undefined): string {
  if (value === null || value === undefined) return '—';
  return Number(value).toFixed(1);
}
