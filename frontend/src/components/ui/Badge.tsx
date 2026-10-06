import { CheckCircle2, ShieldAlert } from 'lucide-react';
import type { ReactNode } from 'react';
import { cn } from '@/lib/cn';
import { GRADE_LABEL, SCAN_STATUS_LABEL, SEVERITY_LABEL, STATUS_LABEL } from '@/lib/format';
import type { AssetCriticality, FindingStatus, Grade, ScanStatus, Severity } from '@/lib/types';
import { GRADE_STYLE, SEVERITY_STYLE } from './styles';

export function SeverityBadge({ severity, compact = false }: { severity: Severity; compact?: boolean }) {
  const s = SEVERITY_STYLE[severity];
  const Icon = s.icon;
  return (
    <span className={cn('inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-xs font-semibold', s.chip)}>
      <Icon className="size-3.5" aria-hidden />
      {compact ? null : SEVERITY_LABEL[severity]}
      {compact ? <span className="sr-only">{SEVERITY_LABEL[severity]}</span> : null}
    </span>
  );
}

const findingStatusStyle: Record<FindingStatus, string> = {
  OPEN: 'bg-critical/10 text-critical',
  IN_PROGRESS: 'bg-amber-500/10 text-amber-500 dark:text-amber-400',
  VERIFYING: 'bg-indigo-500/10 text-indigo-500 dark:text-indigo-400',
  RESOLVED: 'bg-good/12 text-good-text',
  ACCEPTED: 'bg-accent/12 text-accent-strong',
  FALSE_POSITIVE: 'bg-surface-2 text-ink-2',
};

export function FindingStatusBadge({ status }: { status: FindingStatus }) {
  return (
    <span className={cn('inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium', findingStatusStyle[status])}>
      {STATUS_LABEL[status]}
    </span>
  );
}

const scanStatusStyle: Record<ScanStatus, { chip: string; pulse?: boolean }> = {
  PENDING: { chip: 'bg-surface-2 text-ink-2' },
  RUNNING: { chip: 'bg-accent/12 text-accent-strong', pulse: true },
  COMPLETED: { chip: 'bg-good/12 text-good-text' },
  FAILED: { chip: 'bg-critical/10 text-critical' },
  CANCELLED: { chip: 'bg-surface-2 text-muted' },
};

export function ScanStatusBadge({ status }: { status: ScanStatus }) {
  const s = scanStatusStyle[status];
  return (
    <span className={cn('inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 text-xs font-medium', s.chip)}>
      {s.pulse ? <span className="size-1.5 animate-pulse rounded-full bg-current" aria-hidden /> : null}
      {SCAN_STATUS_LABEL[status]}
    </span>
  );
}

export function GradeBadge({ grade, size = 'md' }: { grade: Grade | null; size?: 'sm' | 'md' }) {
  if (!grade) {
    return (
      <span className={cn('inline-flex items-center justify-center rounded-md bg-surface-2 font-semibold text-muted', size === 'sm' ? 'h-6 min-w-6 px-1.5 text-xs' : 'h-8 min-w-8 px-2 text-sm')} title="Sin evaluar">
        —
      </span>
    );
  }
  const g = GRADE_STYLE[grade];
  return (
    <span
      title={GRADE_LABEL[grade]}
      className={cn('inline-flex items-center justify-center rounded-md font-bold text-white', g.bg, size === 'sm' ? 'h-6 min-w-6 px-1.5 text-xs' : 'h-8 min-w-8 px-2 text-sm')}
    >
      {grade}
    </span>
  );
}

export function Pill({ children, className }: { children: ReactNode; className?: string }) {
  return <span className={cn('inline-flex items-center gap-1 rounded-full border border-border px-2 py-0.5 text-xs text-ink-2', className)}>{children}</span>;
}

export function GoodIcon() {
  return <CheckCircle2 className="size-4 text-good" aria-hidden />;
}

const criticalityStyle: Record<AssetCriticality, { chip: string; label: string }> = {
  CRITICAL: { chip: 'bg-critical/15 text-critical border border-critical/30', label: 'Crítico (1.5x)' },
  HIGH: { chip: 'bg-warning/15 text-[#8a5b00] dark:text-warning border border-warning/30', label: 'Alto (1.25x)' },
  MEDIUM: { chip: 'bg-surface-2 text-ink-2 border border-border', label: 'Medio (1.0x)' },
  LOW: { chip: 'bg-accent/10 text-accent border border-accent/20', label: 'Bajo (0.75x)' },
};

export function CriticalityBadge({ criticality }: { criticality?: AssetCriticality | null }) {
  const c = (criticality && criticalityStyle[criticality]) ? criticalityStyle[criticality] : criticalityStyle.MEDIUM;
  return (
    <span className={cn('inline-flex items-center rounded-md px-1.5 py-0.5 text-[11px] font-semibold', c.chip)}>
      {c.label}
    </span>
  );
}

export function CisaKevBadge({ ransomware = false }: { ransomware?: boolean }) {
  return (
    <span
      className="inline-flex items-center gap-1 rounded-md bg-critical/15 px-1.5 py-0.5 text-[11px] font-bold text-critical border border-critical/30"
      title="Catálogo CISA KEV: vulnerabilidad explotada activamente en incidentes reales"
    >
      <ShieldAlert className="size-3 text-critical" aria-hidden />
      CISA KEV{ransomware ? ' · Ransomware' : ''}
    </span>
  );
}

export function EpssBadge({ epss, percentile }: { epss?: number | null; percentile?: number | null }) {
  if (epss === undefined || epss === null) return null;
  const pct = (epss * 100).toFixed(1);
  const isHigh = epss >= 0.36;
  const isMedium = epss >= 0.1 && epss < 0.36;

  const style = isHigh
    ? 'bg-critical/15 text-critical border border-critical/30 font-bold'
    : isMedium
      ? 'bg-warning/15 text-[#8a5b00] dark:text-warning border border-warning/30'
      : 'bg-surface-2 text-ink-2 border border-border';

  const percentileText = percentile !== null && percentile !== undefined ? ` · p${(percentile * 100).toFixed(0)}` : '';

  return (
    <span
      className={cn('inline-flex items-center rounded-md px-1.5 py-0.5 text-[11px]', style)}
      title={`FIRST EPSS: Probabilidad de explotación estadística en ataques reales ${pct}%${percentileText}`}
    >
      EPSS {pct}%{percentileText}
    </span>
  );
}

