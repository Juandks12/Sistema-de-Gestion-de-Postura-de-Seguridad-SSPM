import { AlertOctagon, AlertTriangle, CircleAlert, Info, MinusCircle, type LucideIcon } from 'lucide-react';
import type { Grade, Severity } from '@/lib/types';

/**
 * Los colores de estado nunca van solos: siempre acompañan a un icono y una
 * etiqueta, para que la severidad se lea también sin color.
 */
export const SEVERITY_STYLE: Record<Severity, { icon: LucideIcon; dot: string; chip: string; text: string }> = {
  CRITICAL: { icon: AlertOctagon, dot: 'bg-critical', chip: 'bg-critical/12 text-critical', text: 'text-critical' },
  HIGH: { icon: AlertTriangle, dot: 'bg-serious', chip: 'bg-serious/15 text-[#b4532f] dark:text-serious', text: 'text-[#b4532f] dark:text-serious' },
  MEDIUM: { icon: CircleAlert, dot: 'bg-warning', chip: 'bg-warning/18 text-[#8a5b00] dark:text-warning', text: 'text-[#8a5b00] dark:text-warning' },
  LOW: { icon: Info, dot: 'bg-accent', chip: 'bg-accent/12 text-accent-strong', text: 'text-accent-strong' },
  INFO: { icon: MinusCircle, dot: 'bg-muted', chip: 'bg-surface-2 text-ink-2', text: 'text-ink-2' },
};

export const GRADE_STYLE: Record<Grade, { bg: string; text: string; ring: string }> = {
  A: { bg: 'bg-good', text: 'text-good-text', ring: 'stroke-good' },
  B: { bg: 'bg-accent', text: 'text-accent-strong', ring: 'stroke-accent' },
  C: { bg: 'bg-warning', text: 'text-[#8a5b00] dark:text-warning', ring: 'stroke-warning' },
  D: { bg: 'bg-serious', text: 'text-[#b4532f] dark:text-serious', ring: 'stroke-serious' },
  F: { bg: 'bg-critical', text: 'text-critical', ring: 'stroke-critical' },
};

